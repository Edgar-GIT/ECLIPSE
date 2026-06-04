package utils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type WindowsResourceConfig struct {
	Dir             string
	SysoName        string
	IconPath        string
	FileDescription string
	CompanyName     string
	ProductName     string
	ProductVersion  string
}

func PrepareWindowsResource(cfg WindowsResourceConfig) (func(), error) {
	hasIcon := strings.TrimSpace(cfg.IconPath) != ""
	hasInfo := strings.TrimSpace(cfg.FileDescription) != "" ||
		strings.TrimSpace(cfg.CompanyName) != "" ||
		strings.TrimSpace(cfg.ProductName) != "" ||
		strings.TrimSpace(cfg.ProductVersion) != ""

	if !hasIcon && !hasInfo {
		return func() {}, nil
	}

	if strings.TrimSpace(cfg.Dir) == "" {
		cfg.Dir = "."
	}
	if strings.TrimSpace(cfg.SysoName) == "" {
		cfg.SysoName = "rsrc.syso"
	}

	if err := os.MkdirAll(cfg.Dir, 0755); err != nil {
		return nil, err
	}

	if hasInfo {
		return prepareWindresResource(cfg)
	}
	return prepareRsrcResource(cfg)
}

func prepareRsrcResource(cfg WindowsResourceConfig) (func(), error) {
	if err := EnsureRsrcInstalled(); err != nil {
		return nil, err
	}

	icoPath, cleanupIco, err := MaterializeICO(cfg.IconPath)
	if err != nil {
		return nil, err
	}

	sysoPath := filepath.Join(cfg.Dir, cfg.SysoName)
	_ = os.Remove(sysoPath)

	cmd := exec.Command("rsrc", "-ico", icoPath, "-o", sysoPath)
	cmd.Dir = cfg.Dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		cleanupIco()
		return nil, fmt.Errorf("rsrc failed: %v\nOutput: %s", err, string(output))
	}

	return func() {
		cleanupIco()
		_ = os.Remove(sysoPath)
	}, nil
}

func prepareWindresResource(cfg WindowsResourceConfig) (func(), error) {
	windres, err := findWindres()
	if err != nil {
		return nil, err
	}

	cleanupIco := func() {}
	icoPath := ""
	if strings.TrimSpace(cfg.IconPath) != "" {
		icoPath, cleanupIco, err = MaterializeICO(cfg.IconPath)
		if err != nil {
			return nil, err
		}
	}

	sysoPath := filepath.Join(cfg.Dir, cfg.SysoName)
	_ = os.Remove(sysoPath)

	rcFile, err := os.CreateTemp(cfg.Dir, "eclipse-resource-*.rc")
	if err != nil {
		cleanupIco()
		return nil, err
	}
	rcPath := rcFile.Name()
	rcContent := buildWindowsRC(cfg, icoPath)
	if _, err := rcFile.WriteString(rcContent); err != nil {
		rcFile.Close()
		cleanupIco()
		_ = os.Remove(rcPath)
		return nil, err
	}
	if err := rcFile.Close(); err != nil {
		cleanupIco()
		_ = os.Remove(rcPath)
		return nil, err
	}

	cmd := exec.Command(windres, rcPath, "-O", "coff", "-o", sysoPath)
	cmd.Dir = cfg.Dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		cleanupIco()
		_ = os.Remove(rcPath)
		_ = os.Remove(sysoPath)
		return nil, fmt.Errorf("windres failed: %v\nOutput: %s", err, string(output))
	}

	return func() {
		cleanupIco()
		_ = os.Remove(rcPath)
		_ = os.Remove(sysoPath)
	}, nil
}

func EnsureRsrcInstalled() error {
	if _, err := exec.LookPath("rsrc"); err == nil {
		return nil
	}

	fmt.Printf("%s[*] Installing rsrc tool...%s\n", Yellow, Reset)
	cmd := exec.Command("go", "install", "github.com/akavel/rsrc@latest")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install rsrc: %v\nOutput: %s", err, string(output))
	}

	if _, err := exec.LookPath("rsrc"); err != nil {
		return fmt.Errorf("rsrc installed but not found in PATH. Make sure GOPATH/bin is in your PATH")
	}

	return nil
}

func findWindres() (string, error) {
	for _, name := range []string{"windres", "x86_64-w64-mingw32-windres", "i686-w64-mingw32-windres"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("windres not found; install MinGW-w64 to embed Windows file details")
}

func buildWindowsRC(cfg WindowsResourceConfig, icoPath string) string {
	description := defaultString(cfg.FileDescription, "ECLIPSE")
	company := defaultString(cfg.CompanyName, "ECLIPSE")
	product := defaultString(cfg.ProductName, description)
	version := defaultString(cfg.ProductVersion, "1.0.0")
	versionTuple := versionTuple(version)

	var b strings.Builder
	if strings.TrimSpace(icoPath) != "" {
		b.WriteString("IDI_ICON1 ICON \"")
		b.WriteString(escapeRCString(icoPath))
		b.WriteString("\"\n\n")
	}
	fmt.Fprintf(&b, "1 VERSIONINFO\n")
	fmt.Fprintf(&b, "FILEVERSION %s\n", versionTuple)
	fmt.Fprintf(&b, "PRODUCTVERSION %s\n", versionTuple)
	fmt.Fprintf(&b, "FILEOS 0x40004L\n")
	fmt.Fprintf(&b, "FILETYPE 0x1L\n")
	fmt.Fprintf(&b, "BEGIN\n")
	fmt.Fprintf(&b, "  BLOCK \"StringFileInfo\"\n")
	fmt.Fprintf(&b, "  BEGIN\n")
	fmt.Fprintf(&b, "    BLOCK \"040904B0\"\n")
	fmt.Fprintf(&b, "    BEGIN\n")
	fmt.Fprintf(&b, "      VALUE \"CompanyName\", \"%s\\0\"\n", escapeRCString(company))
	fmt.Fprintf(&b, "      VALUE \"FileDescription\", \"%s\\0\"\n", escapeRCString(description))
	fmt.Fprintf(&b, "      VALUE \"FileVersion\", \"%s\\0\"\n", escapeRCString(version))
	fmt.Fprintf(&b, "      VALUE \"InternalName\", \"%s\\0\"\n", escapeRCString(product))
	fmt.Fprintf(&b, "      VALUE \"OriginalFilename\", \"%s\\0\"\n", escapeRCString(product))
	fmt.Fprintf(&b, "      VALUE \"ProductName\", \"%s\\0\"\n", escapeRCString(product))
	fmt.Fprintf(&b, "      VALUE \"ProductVersion\", \"%s\\0\"\n", escapeRCString(version))
	fmt.Fprintf(&b, "    END\n")
	fmt.Fprintf(&b, "  END\n")
	fmt.Fprintf(&b, "  BLOCK \"VarFileInfo\"\n")
	fmt.Fprintf(&b, "  BEGIN\n")
	fmt.Fprintf(&b, "    VALUE \"Translation\", 0x409, 1200\n")
	fmt.Fprintf(&b, "  END\n")
	fmt.Fprintf(&b, "END\n")
	return b.String()
}

func versionTuple(version string) string {
	re := regexp.MustCompile(`\d+`)
	matches := re.FindAllString(version, -1)
	parts := make([]string, 0, 4)
	for _, match := range matches {
		n, err := strconv.Atoi(match)
		if err != nil {
			continue
		}
		if n > 65535 {
			n = 65535
		}
		parts = append(parts, strconv.Itoa(n))
		if len(parts) == 4 {
			break
		}
	}
	for len(parts) < 4 {
		if len(parts) == 0 {
			parts = append(parts, "1")
		} else {
			parts = append(parts, "0")
		}
	}
	return strings.Join(parts, ",")
}

func defaultString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func escapeRCString(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}
