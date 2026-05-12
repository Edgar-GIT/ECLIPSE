//go:build !windows

package cookies

func decryptData(data []byte) ([]byte, error) {

	return data, nil
}
