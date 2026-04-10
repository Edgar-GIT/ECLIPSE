//go:build !windows
// +build !windows

package cookies

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

func decryptData(data []byte) ([]byte, error) {
	// On Linux, DPAPI is not available
	// Cookies are stored either:
	// 1. Encrypted with a key stored in ~/.local/share/google-chrome/ProfileName/
	// 2. Or plaintext in older versions
	// For now, return as-is and let ChromeKatz-style extraction handle it
	return data, nil
}

func extractChromeKeyLinux(profilePath string) ([]byte, error) {
	// On Linux, Chrome stores the encryption key in the LocalState file
	// Read Local State and extract the key using PBKDF2
	localStatePath := profilePath + "/../Local State"

	raw, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Local State: %w", err)
	}

	var state struct {
		OsCrypt struct {
			EncryptedKey      string `json:"encrypted_key"`
			EncryptionMethods struct {
				AES_GCM string `json:"aes_gcm"`
			} `json:"encryption_methods"`
		} `json:"os_crypt"`
	}

	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("failed to parse Local State: %w", err)
	}

	// On Linux, try to get the key from GNOME keyring using secret-tool
	cmd := exec.Command("secret-tool", "lookup", "xdg:schema", "org.chromium.Secret")
	output, err := cmd.Output()
	if err == nil {
		return output, nil
	}

	// Fallback: use PBKDF2 with "peanuts" salt (default for Linux Chrome 80+)
	// This is a simplified approach - full implementation would need proper PBKDF2
	return deriveChromeKeyLinux()
}

func deriveChromeKeyLinux() ([]byte, error) {
	// Chrome on Linux v80+ uses PBKDF2 with salt "Salt"
	// The key is derived from the OS password/login
	// For automated extraction, try environment or default approach

	// Try getting from environment first
	if envKey := os.Getenv("CHROME_ENCRYPTION_KEY"); envKey != "" {
		return []byte(envKey), nil
	}

	// Default: attempt to use the login password
	// This requires user interaction or password prompt
	// For headless operation, return error
	return nil, fmt.Errorf("encryption key not available on Linux without GNOME keyring")
}
