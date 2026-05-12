//go:build !windows

package cookies

import (
	"fmt"
)

type ProcessMemoryExtractor struct{}

func FindChromeProcess() (uint32, error) {
	return 0, fmt.Errorf("memory extraction not supported on this platform")
}

func NewMemoryExtractor(processID uint32) (*ProcessMemoryExtractor, error) {
	return nil, fmt.Errorf("memory extraction not supported on this platform")
}

func (pe *ProcessMemoryExtractor) Close() error {
	return nil
}

func ExtractCookiesFromMemory() ([]BrowserCookie, error) {
	return nil, fmt.Errorf("memory extraction not supported on this platform")
}

func ListChromeProcesses() ([]map[string]interface{}, error) {
	return nil, fmt.Errorf("process listing not supported on this platform")
}
