package portscanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"programa/utils"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type PortInfo struct {
	Port            int       `json:"port"`
	Status          string    `json:"status"` // "open" or "closed"
	Service         string    `json:"service,omitempty"`
	Banner          string    `json:"banner,omitempty"`
	Version         string    `json:"version,omitempty"`
	Vulnerabilities []string  `json:"vulnerabilities,omitempty"`
	LastScanned     time.Time `json:"last_scanned"`
}

type PortScanResults struct {
	TargetIP     string     `json:"target_ip"`
	TotalScanned int        `json:"total_scanned"`
	Open         int        `json:"open"`
	Closed       int        `json:"closed"`
	ScanDuration float64    `json:"scan_duration_seconds"`
	ScannedAt    time.Time  `json:"scanned_at"`
	Ports        []PortInfo `json:"ports"`

	ScanMode  string `json:"scan_mode,omitempty"`
	StartPort int    `json:"start_port,omitempty"`
	EndPort   int    `json:"end_port,omitempty"`
}

const portResultsFile = "port_scan_results.json"

var commonPortServices = map[int]string{
	20:    "FTP-Data",
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	6379:  "Redis",
	27017: "MongoDB",
	8080:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
}

var fastScanPorts = []int{
	20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 135, 137, 138, 139, 143, 161, 389, 443,
	445, 465, 514, 587, 631, 993, 995, 1080, 1433, 1521, 1723, 1883, 2049, 2375, 2376, 3000,
	3128, 3306, 3389, 4000, 5000, 5432, 5672, 5900, 5984, 6379, 6443, 6667, 7001, 8000, 8008,
	8080, 8081, 8088, 8090, 8443, 8888, 9000, 9042, 9092, 9200, 9300, 11211, 15672, 27017,
}

var cveDatabase = map[string][]string{
	"telnet": {"Insecure protocol: credentials sent in cleartext (disable Telnet)."},
	"ftp":    {"Insecure protocol: unencrypted data/control channels (prefer SFTP/FTPS)."},
	"mysql":  {"MySQL exposed on 3306: potential brute-force target if externally reachable."},
	"smb": {
		"CVE-2017-0144 (EternalBlue): SMB services may be vulnerable if patching is outdated.",
		"SMB exposed to untrusted networks: lateral movement and ransomware risk.",
	},
	"rdp": {
		"CVE-2019-0708 (BlueKeep): legacy RDP stacks may be vulnerable if unpatched.",
		"RDP exposed: enforce NLA, MFA, account lockout, and source IP restrictions.",
	},
	"redis": {
		"Redis exposed: unauthenticated access/misconfiguration can allow data theft or RCE.",
	},
	"mongodb": {
		"MongoDB exposed: verify authentication and bind settings to avoid data exposure.",
	},
	"smtp": {
		"SMTP exposed: verify anti-relay controls and TLS enforcement.",
	},
	"imap_pop3": {
		"IMAP/POP3 exposed: prefer TLS-enabled variants and strong authentication policies.",
	},
	"http": {
		"HTTP service exposed: verify patch level, hardening, and security headers.",
	},
}

func PortScanner() {
	utils.ClearTerminal()
	fmt.Printf("\n%s=== PORT SCANNER ===%s\n\n", utils.Blue, utils.Reset)

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("%s[1] Scan my own IP (auto-detect)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[2] Scan specific IP + specific port%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[3] Scan specific IP + all ports (1-65535)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[4] Fast scan (common important ports)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[5] Return to main menu%s\n", utils.Yellow, utils.Reset)
		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)

		option, _ := reader.ReadString('\n')
		option = strings.TrimSpace(option)

		switch option {
		case "1":
			localIP, err := detectLocalIPv4()
			if err != nil {
				fmt.Printf("%sCould not detect local IP: %v%s\n", utils.Red, err, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}

			fmt.Printf("\n%sDetected local IP: %s%s\n", utils.Yellow, localIP, utils.Reset)
			results := runPortScan(localIP, 1, 65535, true, "local-ip-all")
			savePortResults(results)
			utils.ClearTerminal()
			displayPortResults(&results)
			utils.WaitForEnter(reader)
			return

		case "2":
			fmt.Printf("%sEnter target IP (Enter = my local IP): %s", utils.Green, utils.Reset)
			targetIP, _ := reader.ReadString('\n')
			targetIP = strings.TrimSpace(targetIP)
			if targetIP == "" {
				localIP, err := detectLocalIPv4()
				if err != nil {
					fmt.Printf("%sCould not detect local IP: %v%s\n", utils.Red, err, utils.Reset)
					utils.WaitForEnter(reader)
					return
				}
				targetIP = localIP
				fmt.Printf("%sUsing local IP: %s%s\n", utils.Yellow, targetIP, utils.Reset)
			}
			if !utils.IsValidIPv4(targetIP) {
				fmt.Printf("%sInvalid IPv4 address.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}

			fmt.Printf("%sEnter target port (1-65535): %s", utils.Green, utils.Reset)
			portStr, _ := reader.ReadString('\n')
			port, err := strconv.Atoi(strings.TrimSpace(portStr))
			if err != nil || port < 1 || port > 65535 {
				fmt.Printf("%sInvalid port. Must be between 1 and 65535.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}

			results := runPortScan(targetIP, port, port, false, "single-port")
			savePortResults(results)
			utils.ClearTerminal()
			displayPortResults(&results)
			utils.WaitForEnter(reader)
			return

		case "3":
			fmt.Printf("%sEnter target IP: %s", utils.Green, utils.Reset)
			targetIP, _ := reader.ReadString('\n')
			targetIP = strings.TrimSpace(targetIP)
			if !utils.IsValidIPv4(targetIP) {
				fmt.Printf("%sInvalid IPv4 address.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}

			results := runPortScan(targetIP, 1, 65535, true, "full-range")
			savePortResults(results)
			utils.ClearTerminal()
			displayPortResults(&results)
			utils.WaitForEnter(reader)
			return

		case "4":
			fmt.Printf("%sEnter target IP (Enter = my local IP): %s", utils.Green, utils.Reset)
			targetIP, _ := reader.ReadString('\n')
			targetIP = strings.TrimSpace(targetIP)
			if targetIP == "" {
				localIP, err := detectLocalIPv4()
				if err != nil {
					fmt.Printf("%sCould not detect local IP: %v%s\n", utils.Red, err, utils.Reset)
					utils.WaitForEnter(reader)
					return
				}
				targetIP = localIP
				fmt.Printf("%sUsing local IP: %s%s\n", utils.Yellow, targetIP, utils.Reset)
			}
			if !utils.IsValidIPv4(targetIP) {
				fmt.Printf("%sInvalid IPv4 address.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}

			results := runPortListScan(targetIP, fastScanPorts, true, "fast-scan")
			savePortResults(results)
			utils.ClearTerminal()
			utils.Banner()
			displayPortResults(&results)
			utils.WaitForEnter(reader)
			return

		case "5":
			return

		default:
			fmt.Printf("%sInvalid option!%s\n\n", utils.Red, utils.Reset)
		}
	}
}

func ViewPortScanResults() {
	utils.ClearTerminal()
	fmt.Printf("\n%s=== PORT SCAN RESULTS ===%s\n\n", utils.Blue, utils.Reset)

	results, err := loadPortResults()
	if err != nil {
		fmt.Printf("%sNo port scan results found. Run a scan first!%s\n", utils.Red, utils.Reset)
		reader := bufio.NewReader(os.Stdin)
		utils.WaitForEnter(reader)
		return
	}

	displayPortResults(results)

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("\n%sOptions:%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s[1] Refresh scan (re-scan same IP/ports)%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[2] Delete results%s\n", utils.Red, utils.Reset)
	fmt.Printf("%s[3] Return to menu%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("\n%sChoose option: %s", utils.Green, utils.Reset)

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	switch input {
	case "1":
		refreshPortResults(results)
	case "2":
		deletePortResults()
	case "3":
		return
	default:
		fmt.Printf("%sInvalid option!%s\n", utils.Red, utils.Reset)
		time.Sleep(2 * time.Second)
	}
}

func runPortScan(targetIP string, startPort, endPort int, showProgress bool, scanMode string) PortScanResults {
	if startPort < 1 {
		startPort = 1
	}
	if endPort > 65535 {
		endPort = 65535
	}
	if startPort > endPort {
		startPort, endPort = endPort, startPort
	}

	ports := make([]int, 0, endPort-startPort+1)
	for p := startPort; p <= endPort; p++ {
		ports = append(ports, p)
	}

	return runPortListScan(targetIP, ports, showProgress, scanMode)
}

func runPortListScan(targetIP string, ports []int, showProgress bool, scanMode string) PortScanResults {
	total := len(ports)
	if total == 0 {
		return PortScanResults{
			TargetIP:     targetIP,
			TotalScanned: 0,
			Open:         0,
			Closed:       0,
			ScanDuration: 0,
			ScannedAt:    time.Now(),
			Ports:        []PortInfo{},
			ScanMode:     scanMode,
		}
	}

	sort.Ints(ports)
	startPort := ports[0]
	endPort := ports[len(ports)-1]

	fmt.Printf("\n%sScanning %s on %s (%d targets)...%s\n\n", utils.Yellow, scanMode, targetIP, total, utils.Reset)
	if total > 1000 {
		estimatedUpper := float64(total) * 2.0 / 100.0
		fmt.Printf("%sEstimated upper bound: ~%.1f minutes in worst-case timeout scenarios.%s\n\n", utils.Yellow, estimatedUpper/60.0, utils.Reset)
	}

	startTime := time.Now()
	resultsCh := make(chan PortInfo, total)
	semaphore := make(chan struct{}, 100)
	var wg sync.WaitGroup
	var completed int64

	for _, port := range ports {
		semaphore <- struct{}{}
		wg.Add(1)

		go func(p int) {
			defer wg.Done()
			defer func() { <-semaphore }()
			resultsCh <- scanSinglePort(targetIP, p)
		}(port)
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	doneProgress := make(chan struct{})
	if showProgress {
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-doneProgress:
					return
				case <-ticker.C:
					done := int(atomic.LoadInt64(&completed))
					if done == 0 {
						fmt.Printf("%s[Progress] 0/%d ports scanned...%s\n", utils.Blue, total, utils.Reset)
						continue
					}

					elapsed := time.Since(startTime).Seconds()
					rate := float64(done) / elapsed
					remaining := 0.0
					if rate > 0 {
						remaining = float64(total-done) / rate
					}

					eta := fmt.Sprintf("%.0fs", math.Max(0, remaining))
					fmt.Printf("%s[Progress] %d/%d (%.1f%%) | rate %.1f p/s | ETA %s%s\n",
						utils.Blue, done, total, (float64(done)/float64(total))*100.0, rate, eta, utils.Reset)
				}
			}
		}()
	}

	resultPorts := make([]PortInfo, 0, total)
	for portInfo := range resultsCh {
		resultPorts = append(resultPorts, portInfo)
		processed := int(atomic.AddInt64(&completed, 1))

		if showProgress && processed%1000 == 0 {
			fmt.Printf("%s[Progress] %d/%d ports scanned...%s\n", utils.Blue, processed, total, utils.Reset)
		}
	}
	close(doneProgress)

	sort.Slice(resultPorts, func(i, j int) bool {
		return resultPorts[i].Port < resultPorts[j].Port
	})

	openCount := 0
	for _, p := range resultPorts {
		if p.Status == "open" {
			openCount++
		}
	}

	duration := time.Since(startTime).Seconds()
	return PortScanResults{
		TargetIP:     targetIP,
		TotalScanned: total,
		Open:         openCount,
		Closed:       total - openCount,
		ScanDuration: duration,
		ScannedAt:    time.Now(),
		Ports:        resultPorts,
		ScanMode:     scanMode,
		StartPort:    startPort,
		EndPort:      endPort,
	}
}

func scanSinglePort(targetIP string, port int) PortInfo {
	info := PortInfo{
		Port:        port,
		Status:      "closed",
		LastScanned: time.Now(),
	}

	address := net.JoinHostPort(targetIP, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return info
	}
	defer conn.Close()

	info.Status = "open"
	info.Service = detectService(port)
	info.Banner, info.Version = grabAndFingerprint(conn, port, info.Service)
	info.Service = inferServiceFrom(info.Service, info.Banner)
	if info.Version == "" {
		info.Version = extractVersion(info.Banner)
	}
	info.Vulnerabilities = detectPortVulnerabilities(port, info.Service, info.Version, info.Banner)

	return info
}

func detectService(port int) string {
	if svc, ok := commonPortServices[port]; ok {
		return svc
	}
	return "Unknown"
}

func grabAndFingerprint(conn net.Conn, port int, baseService string) (string, string) {
	_ = conn.SetDeadline(time.Now().Add(1200 * time.Millisecond))

	buffer := make([]byte, 512)
	n, _ := conn.Read(buffer)

	if n == 0 {
		probe := serviceProbe(port, baseService)
		if probe != "" {
			_, _ = conn.Write([]byte(probe))
			n, _ = conn.Read(buffer)
		}
	}

	if n <= 0 {
		return "", ""
	}

	banner := sanitize(buffer[:n])
	version := extractVersion(banner)
	return banner, version
}

func serviceProbe(port int, service string) string {
	if port == 80 || port == 8080 || port == 443 || port == 8443 || strings.Contains(strings.ToLower(service), "http") {
		return "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"
	}
	if port == 25 {
		return "EHLO scanner.local\r\n"
	}
	if port == 110 {
		return "CAPA\r\n"
	}
	if port == 143 {
		return "a001 CAPABILITY\r\n"
	}
	return ""
}

func sanitize(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}

	clean := strings.Map(func(r rune) rune {
		if r >= 32 && r <= 126 || r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		return -1
	}, string(raw))

	clean = strings.TrimSpace(clean)
	if clean == "" {
		return ""
	}

	lines := strings.Split(clean, "\n")
	first := strings.TrimSpace(lines[0])
	if len(first) > 220 {
		first = first[:220]
	}
	return first
}

func extractVersion(banner string) string {
	if banner == "" {
		return ""
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)OpenSSH[_/ -]?([0-9]+(?:\.[0-9]+){0,3})`),
		regexp.MustCompile(`(?i)Apache/?([0-9]+(?:\.[0-9]+){0,3})`),
		regexp.MustCompile(`(?i)nginx/?([0-9]+(?:\.[0-9]+){0,3})`),
		regexp.MustCompile(`(?i)PostgreSQL[ /-]?([0-9]+(?:\.[0-9]+){0,3})`),
		regexp.MustCompile(`(?i)MySQL[ /-]?([0-9]+(?:\.[0-9]+){0,3})`),
		regexp.MustCompile(`(?i)([0-9]+(?:\.[0-9]+){1,3})`),
	}

	for _, re := range patterns {
		match := re.FindStringSubmatch(banner)
		if len(match) > 1 {
			return match[1]
		}
	}

	return ""
}

func detectPortVulnerabilities(port int, service, version, banner string) []string {
	var vulns []string
	serviceLower := strings.ToLower(service + " " + banner)

	if port == 23 || strings.Contains(serviceLower, "telnet") {
		vulns = append(vulns, cveDatabase["telnet"]...)
	}
	if port == 21 || strings.Contains(serviceLower, "ftp") {
		vulns = append(vulns, cveDatabase["ftp"]...)
	}
	if port == 3306 || strings.Contains(serviceLower, "mysql") {
		vulns = append(vulns, cveDatabase["mysql"]...)
	}
	if port == 445 || strings.Contains(serviceLower, "smb") {
		vulns = append(vulns, cveDatabase["smb"]...)
	}
	if port == 3389 || strings.Contains(serviceLower, "rdp") {
		vulns = append(vulns, cveDatabase["rdp"]...)
	}
	if port == 6379 || strings.Contains(serviceLower, "redis") {
		vulns = append(vulns, cveDatabase["redis"]...)
	}
	if port == 27017 || strings.Contains(serviceLower, "mongodb") {
		vulns = append(vulns, cveDatabase["mongodb"]...)
	}
	if port == 25 || strings.Contains(serviceLower, "smtp") {
		vulns = append(vulns, cveDatabase["smtp"]...)
	}
	if port == 110 || port == 143 || strings.Contains(serviceLower, "pop3") || strings.Contains(serviceLower, "imap") {
		vulns = append(vulns, cveDatabase["imap_pop3"]...)
	}
	if port == 80 || port == 8080 || strings.Contains(serviceLower, "http") {
		vulns = append(vulns, cveDatabase["http"]...)
	}

	sshVersion := version
	if sshVersion == "" {
		sshVersion = extractVersionFromText(serviceLower, `openssh[_/ -]?([0-9]+(?:\.[0-9]+){0,3})`)
	}
	if strings.Contains(serviceLower, "ssh") && sshVersion != "" && compareSemanticVersion(sshVersion, "7.4") < 0 {
		vulns = append(vulns, "CVE-2016-6210: OpenSSH < 7.4 potentially vulnerable to username enumeration.")
	}
	if strings.Contains(serviceLower, "ssh") && sshVersion != "" && compareSemanticVersion(sshVersion, "8.2") < 0 {
		vulns = append(vulns, "CVE-2020-14145: OpenSSH clients/servers below safer baselines may have information leak risks.")
	}

	apacheVersion := version
	if apacheVersion == "" {
		apacheVersion = extractVersionFromText(serviceLower, `apache/?([0-9]+(?:\.[0-9]+){0,3})`)
	}
	if strings.Contains(serviceLower, "apache") && apacheVersion != "" && compareSemanticVersion(apacheVersion, "2.4.49") < 0 {
		vulns = append(vulns, "CVE-2021-41773: Apache < 2.4.49 potentially vulnerable to path traversal/RCE.")
	}
	if strings.Contains(serviceLower, "apache") && apacheVersion != "" && compareSemanticVersion(apacheVersion, "2.4.50") < 0 {
		vulns = append(vulns, "CVE-2021-42013: Apache < 2.4.50 may remain vulnerable after incomplete previous fixes.")
	}

	nginxVersion := version
	if nginxVersion == "" {
		nginxVersion = extractVersionFromText(serviceLower, `nginx/?([0-9]+(?:\.[0-9]+){0,3})`)
	}
	if strings.Contains(serviceLower, "nginx") && nginxVersion != "" && compareSemanticVersion(nginxVersion, "1.17.7") < 0 {
		vulns = append(vulns, "CVE-2019-20372: Older Nginx versions may be vulnerable to HTTP/2-related request smuggling conditions.")
	}

	postgresVersion := version
	if postgresVersion == "" {
		postgresVersion = extractVersionFromText(serviceLower, `postgres(?:ql)?[ /-]?([0-9]+(?:\.[0-9]+){0,3})`)
	}
	if port == 5432 || strings.Contains(serviceLower, "postgres") {
		vulns = append(vulns, "PostgreSQL exposed on 5432: enforce SCRAM auth, TLS, and network ACL restrictions.")
		if postgresVersion != "" && compareSemanticVersion(postgresVersion, "13.0") < 0 {
			vulns = append(vulns, "Older PostgreSQL major versions may contain multiple fixed CVEs; validate patch baseline.")
		}
	}

	if port == 5900 || strings.Contains(serviceLower, "vnc") {
		vulns = append(vulns, "VNC exposed: verify authentication strength and tunnel access through VPN/SSH.")
	}
	if port == 53 || strings.Contains(serviceLower, "dns") {
		vulns = append(vulns, "DNS service exposed: ensure recursion is restricted to trusted networks only.")
	}

	return dedupeStrings(vulns)
}

func inferServiceFrom(currentService, banner string) string {
	if strings.TrimSpace(banner) == "" {
		return currentService
	}

	lb := strings.ToLower(banner)
	switch {
	case strings.Contains(lb, "openssh"):
		return "SSH"
	case strings.Contains(lb, "apache"):
		return "HTTP (Apache)"
	case strings.Contains(lb, "nginx"):
		return "HTTP (Nginx)"
	case strings.Contains(lb, "mysql"):
		return "MySQL"
	case strings.Contains(lb, "postgres"):
		return "PostgreSQL"
	case strings.Contains(lb, "redis"):
		return "Redis"
	case strings.Contains(lb, "mongodb"):
		return "MongoDB"
	case strings.Contains(lb, "smtp"):
		return "SMTP"
	case strings.Contains(lb, "pop3"):
		return "POP3"
	case strings.Contains(lb, "imap"):
		return "IMAP"
	default:
		return currentService
	}
}

func extractVersionFromText(text, pattern string) string {
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(text)
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

func compareSemanticVersion(a, b string) int {
	parse := func(v string) []int {
		parts := strings.Split(v, ".")
		out := make([]int, 0, len(parts))
		for _, p := range parts {
			numeric := regexp.MustCompile(`^\d+`).FindString(p)
			if numeric == "" {
				out = append(out, 0)
				continue
			}
			n, err := strconv.Atoi(numeric)
			if err != nil {
				out = append(out, 0)
				continue
			}
			out = append(out, n)
		}
		return out
	}

	av := parse(a)
	bv := parse(b)
	maxLen := len(av)
	if len(bv) > maxLen {
		maxLen = len(bv)
	}

	for len(av) < maxLen {
		av = append(av, 0)
	}
	for len(bv) < maxLen {
		bv = append(bv, 0)
	}

	for i := 0; i < maxLen; i++ {
		if av[i] < bv[i] {
			return -1
		}
		if av[i] > bv[i] {
			return 1
		}
	}
	return 0
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if strings.TrimSpace(s) == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func savePortResults(results PortScanResults) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("%sError saving port scan results: %v%s\n", utils.Red, err, utils.Reset)
		return
	}

	err = os.WriteFile(portResultsFile, data, 0644)
	if err != nil {
		fmt.Printf("%sError writing file: %v%s\n", utils.Red, err, utils.Reset)
		return
	}

	fmt.Printf("%s\n✓ Port scan results saved to %s%s\n", utils.Green, portResultsFile, utils.Reset)
}

func loadPortResults() (*PortScanResults, error) {
	data, err := os.ReadFile(portResultsFile)
	if err != nil {
		return nil, err
	}

	var results PortScanResults
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, err
	}
	return &results, nil
}

func displayPortResults(results *PortScanResults) {
	fmt.Printf("\n%s╔═══════════════════════════════════════════════════════════════════════════╗%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s║                           PORT SCAN STATISTICS                            ║%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s╚═══════════════════════════════════════════════════════════════════════════╝%s\n", utils.Blue, utils.Reset)

	fmt.Printf("\n%s  Target IP:      %s%s%s\n", utils.Green, utils.Yellow, results.TargetIP, utils.Reset)
	fmt.Printf("%s  Total Scanned:  %s%d%s\n", utils.Green, utils.Yellow, results.TotalScanned, utils.Reset)
	fmt.Printf("%s  Open Ports:     %s%d%s\n", utils.Green, utils.Green, results.Open, utils.Reset)
	fmt.Printf("%s  Closed Ports:   %s%d%s\n", utils.Green, utils.Red, results.Closed, utils.Reset)
	fmt.Printf("%s  Scan Duration:  %s%.2fs%s\n", utils.Green, utils.Yellow, results.ScanDuration, utils.Reset)
	fmt.Printf("%s  Scanned At:     %s%s%s\n\n", utils.Green, utils.Yellow, results.ScannedAt.Format("2006-01-02 15:04:05"), utils.Reset)

	fmt.Printf("%s╔═══════════════════════════════════════════════════════════════════════════╗%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s║                              OPEN PORT DETAILS                            ║%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s╚═══════════════════════════════════════════════════════════════════════════╝%s\n\n", utils.Blue, utils.Reset)

	openPorts := make([]PortInfo, 0, results.Open)
	for _, p := range results.Ports {
		if p.Status == "open" {
			openPorts = append(openPorts, p)
		}
	}

	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})

	if len(openPorts) == 0 {
		fmt.Printf("%sNo open ports found.%s\n\n", utils.Yellow, utils.Reset)
		return
	}

	for _, p := range openPorts {
		fmt.Printf("%s[OPEN] Port %d%s\n", utils.Green, p.Port, utils.Reset)
		fmt.Printf("    %sService:%s %s\n", utils.Blue, utils.Reset, portFieldOrNA(p.Service))
		if strings.TrimSpace(p.Banner) != "" {
			fmt.Printf("    %sBanner:%s %s\n", utils.Blue, utils.Reset, p.Banner)
		}
		if strings.TrimSpace(p.Version) != "" {
			fmt.Printf("    %sVersion:%s %s\n", utils.Blue, utils.Reset, p.Version)
		}

		if len(p.Vulnerabilities) > 0 {
			fmt.Printf("    %sPotential Vulnerabilities:%s\n", utils.Yellow, utils.Reset)
			for _, v := range p.Vulnerabilities {
				color := utils.Yellow
				if strings.Contains(strings.ToUpper(v), "CVE-") {
					color = utils.Red
				}
				fmt.Printf("      %s- %s%s\n", color, v, utils.Reset)
			}
		}
		fmt.Println()
	}
}

func refreshPortResults(previous *PortScanResults) {
	utils.ClearTerminal()
	fmt.Printf("\n%s=== REFRESHING PORT SCAN ===%s\n\n", utils.Blue, utils.Reset)

	if !utils.IsValidIPv4(previous.TargetIP) {
		fmt.Printf("%sCannot refresh: invalid saved target IP.%s\n", utils.Red, utils.Reset)
		reader := bufio.NewReader(os.Stdin)
		utils.WaitForEnter(reader)
		return
	}

	start := previous.StartPort
	end := previous.EndPort
	if start == 0 || end == 0 {
		// Backward compatibility if old results didn't include range fields.
		start = 1
		end = 65535
		if previous.TotalScanned == 1 && len(previous.Ports) == 1 {
			start = previous.Ports[0].Port
			end = previous.Ports[0].Port
		}
	}

	showProgress := start == 1 && end == 65535
	results := runPortScan(previous.TargetIP, start, end, showProgress, "refresh:"+previous.ScanMode)
	savePortResults(results)

	utils.ClearTerminal()
	displayPortResults(&results)

	reader := bufio.NewReader(os.Stdin)
	utils.WaitForEnter(reader)
}

func deletePortResults() {
	err := os.Remove(portResultsFile)
	if err != nil {
		fmt.Printf("%sError deleting results: %v%s\n", utils.Red, err, utils.Reset)
	} else {
		fmt.Printf("%s✓ Port scan results deleted successfully!%s\n", utils.Green, utils.Reset)
	}
	time.Sleep(2 * time.Second)
}

func detectLocalIPv4() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || localAddr.IP == nil || localAddr.IP.To4() == nil {
		return "", fmt.Errorf("could not determine local IPv4")
	}
	return localAddr.IP.String(), nil
}

func portFieldOrNA(v string) string {
	if strings.TrimSpace(v) == "" {
		return "N/A"
	}
	return v
}
