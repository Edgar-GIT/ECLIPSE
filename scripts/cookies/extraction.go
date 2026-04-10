package cookies

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func extractChromeKeyWindowsFromDisk(localStatePath string) ([]byte, error) {
	raw, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, err
	}

	var state struct {
		OsCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, err
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(state.OsCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}

	// Remove DPAPI prefix if present
	if bytes.HasPrefix(encryptedKey, []byte("DPAPI")) {
		encryptedKey = encryptedKey[5:]
	}

	return decryptData(encryptedKey)
}

func extractChromeKeyLinux(cookiesPath string) ([]byte, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	// Try to find Local State file
	possiblePaths := []string{
		filepath.Join(home, ".config", "google-chrome", "Local State"),
		filepath.Join(home, ".config", "google-chrome-stable", "Local State"),
		filepath.Join(home, ".config", "microsoft-edge", "Local State"),
		filepath.Join(home, ".config", "brave", "Local State"),
		filepath.Join(home, ".config", "opera", "Local State"),
	}

	var raw []byte
	for _, path := range possiblePaths {
		data, err := os.ReadFile(path)
		if err == nil {
			raw = data
			break
		}
	}

	if raw == nil {
		return nil, fmt.Errorf("could not find Local State file")
	}

	var state struct {
		OsCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, err
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(state.OsCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}

	// Try to get key from secret-tool (GNOME Keyring)
	if key := getKeyFromGnomeKeyring(); key != nil {
		return key, nil
	}

	// Try environment variable
	if envKey := os.Getenv("CHROME_ENCRYPTION_KEY"); envKey != "" {
		return []byte(envKey), nil
	}

	// Return the encrypted key as-is for fallback handling
	return encryptedKey, nil
}

func getKeyFromGnomeKeyring() []byte {
	// Try secret-tool command
	cmd := exec.Command("secret-tool", "lookup", "xdg:schema", "org.chromium.Secret")
	output, err := cmd.Output()
	if err == nil && len(output) > 0 {
		return bytes.TrimSpace(output)
	}

	// Try dbus-send approach for kde-wallet
	cmd = exec.Command("qdbus", "org.kde.kwalletd5", "/modules/kwalletd5", "networkWallet")
	output, err = cmd.Output()
	if err == nil && len(output) > 0 {
		return bytes.TrimSpace(output)
	}

	return nil
}

func extractCookiesWithKey(cookiesPath string, key []byte) ([]BrowserCookie, error) {
	tempDir, err := os.MkdirTemp("", "cookies_profile")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	tempCookies := filepath.Join(tempDir, "Cookies")
	if err := copyFile(cookiesPath, tempCookies); err != nil {
		// If copy fails due to file being locked, try opening directly
		return extractFromLockedDatabase(cookiesPath, key)
	}

	return extractFromDatabase(tempCookies, key)
}

func extractFromDatabase(dbPath string, key []byte) ([]BrowserCookie, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT host_key, name, path, expires_utc, is_secure, is_httponly, last_access_utc, encrypted_value FROM cookies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cookies []BrowserCookie
	for rows.Next() {
		var host, name, path string
		var expiresUTC int64
		var secure, httponly int
		var lastAccess int64
		var encrypted []byte

		if err := rows.Scan(&host, &name, &path, &expiresUTC, &secure, &httponly, &lastAccess, &encrypted); err != nil {
			continue
		}

		value, err := decryptChromeCookie(encrypted, key)
		if err != nil {
			value = fmt.Sprintf("[encrypted: %s]", err.Error())
		}

		cookies = append(cookies, BrowserCookie{
			Host:       host,
			Name:       name,
			Value:      value,
			Path:       path,
			Expires:    convertWebkitTime(expiresUTC),
			Secure:     secure != 0,
			HttpOnly:   httponly != 0,
			LastAccess: convertWebkitTime(lastAccess),
		})
	}

	return cookies, nil
}

func extractFromLockedDatabase(dbPath string, key []byte) ([]BrowserCookie, error) {
	// If database is locked by running browser, try to access it anyway
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT host_key, name, path, expires_utc, is_secure, is_httponly, last_access_utc, encrypted_value FROM cookies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cookies []BrowserCookie
	for rows.Next() {
		var host, name, path string
		var expiresUTC int64
		var secure, httponly int
		var lastAccess int64
		var encrypted []byte

		if err := rows.Scan(&host, &name, &path, &expiresUTC, &secure, &httponly, &lastAccess, &encrypted); err != nil {
			continue
		}

		value, err := decryptChromeCookie(encrypted, key)
		if err != nil {
			value = fmt.Sprintf("[encrypted: %s]", err.Error())
		}

		cookies = append(cookies, BrowserCookie{
			Host:       host,
			Name:       name,
			Value:      value,
			Path:       path,
			Expires:    convertWebkitTime(expiresUTC),
			Secure:     secure != 0,
			HttpOnly:   httponly != 0,
			LastAccess: convertWebkitTime(lastAccess),
		})
	}

	return cookies, nil
}

func decryptChromeCookie(encrypted, key []byte) (string, error) {
	// Handle v10/v11 encrypted cookies (AES-GCM)
	if len(encrypted) >= 15 && (bytes.HasPrefix(encrypted, []byte("v10")) || bytes.HasPrefix(encrypted, []byte("v11"))) {
		return decryptAESGCM(encrypted, key)
	}

	// Handle DPAPI encrypted cookies (Windows)
	if len(encrypted) > 0 {
		decrypted, err := decryptData(encrypted)
		if err == nil && len(decrypted) > 0 {
			return string(decrypted), nil
		}
	}

	return "", fmt.Errorf("unable to decrypt")
}

func decryptAESGCM(encrypted, key []byte) (string, error) {
	// v10/v11 format: [prefix(3 bytes)][nonce(12 bytes)][ciphertext+tag(rest)]
	if len(encrypted) < 15 {
		return "", fmt.Errorf("encrypted data too short")
	}

	nonce := encrypted[3:15]
	ciphertext := encrypted[15:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := srcFile.WriteTo(dstFile); err != nil {
		return err
	}

	return nil
}
