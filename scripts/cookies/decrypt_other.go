//go:build !windows
// +build !windows

package cookies

func decryptData(data []byte) ([]byte, error) {
	// On Linux, DPAPI is not available
	// Key extraction is handled in extraction.go via secret-tool or environment variables
	return data, nil
}
