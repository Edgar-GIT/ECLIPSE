//go:build windows

package cookies

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func decryptData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	inBlob := windows.DataBlob{
		Size: uint32(len(data)),
		Data: &data[0],
	}
	var outBlob windows.DataBlob

	if err := windows.CryptUnprotectData(&inBlob, nil, nil, 0, nil, 0, &outBlob); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.Data)))

	decrypted := make([]byte, outBlob.Size)
	copy(decrypted, unsafe.Slice(outBlob.Data, outBlob.Size))
	return decrypted, nil
}
