package pcutilities

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/process"
)

func reportHomeDir() string {
	if su := strings.TrimSpace(os.Getenv("SUDO_USER")); su != "" {
		if os.Geteuid() == 0 || os.Getuid() == 0 {
			p := filepath.Join("/home", su)
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				return p
			}
		}
	}
	h, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(h) == "" {
		return ""
	}
	return h
}

var wlanNameRe = regexp.MustCompile(`\b(wlan\d+|wlp\w+)\b`)

func wifiIfaceFromSummary(active string) string {
	active = strings.TrimSpace(active)
	if m := wlanNameRe.FindString(strings.ToLower(active)); m != "" {
		return m
	}
	return ""
}

func collectBSSIDIw(iface string) string {
	if iface == "" || runtime.GOOS != "linux" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "iw", "dev", iface, "link")
	b, err := cmd.Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "connected to ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				mac := strings.ToUpper(strings.TrimSuffix(parts[2], ")"))
				if len(mac) >= 11 {
					return mac
				}
			}
		}
		if strings.HasPrefix(low, "addr ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return strings.ToUpper(strings.TrimSpace(parts[1]))
			}
		}
	}
	return ""
}

func resolveWiFiBSSID(r *SystemReport) string {
	s := collectCurrentWiFiBSSID(r.DefaultIface)
	if s != "" {
		return s
	}
	if x := collectBSSIDIw(r.DefaultIface); x != "" {
		return x
	}
	if wi := wifiIfaceFromSummary(r.ActiveConn); wi != "" {
		if x := collectBSSIDIw(wi); x != "" {
			return x
		}
		if s := collectCurrentWiFiBSSID(wi); s != "" {
			return s
		}
	}
	return ""
}

func cleanDULine(s string) string {
	s = strings.TrimSpace(s)
	return strings.TrimLeft(s, "| \t")
}

func collectHomeDiskUsage(home string) (lines []string, largest string) {
	home = strings.TrimSpace(home)
	if home == "" || runtime.GOOS == "windows" {
		return nil, ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c",
		fmt.Sprintf("du -xh --max-depth=1 %q 2>/dev/null | sort -hr | head -n 18", home))
	b, err := cmd.Output()
	if err != nil {
		return nil, ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = cleanDULine(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) > 1 {
		for _, ln := range lines[1:] {
			if strings.HasPrefix(ln, home+string(filepath.Separator)) || strings.Contains(ln, "\t") {
				largest = cleanDULine(ln)
				break
			}
		}
	}
	if largest == "" && len(lines) > 0 {
		largest = cleanDULine(lines[0])
	}
	return lines, largest
}

func collectHomeListing(home string) []string {
	home = strings.TrimSpace(home)
	if home == "" {
		return nil
	}
	de, err := os.ReadDir(home)
	if err != nil {
		return nil
	}
	sort.Slice(de, func(i, j int) bool {
		return strings.ToLower(de[i].Name()) < strings.ToLower(de[j].Name())
	})
	var out []string
	for _, e := range de {
		if len(out) >= 90 {
			break
		}
		nm := e.Name()
		if nm == "." || nm == ".." {
			continue
		}
		inf, err := e.Info()
		mode := "??????????"
		sz := ""
		if err == nil {
			mode = inf.Mode().String()
			if inf.IsDir() {
				sz = "<dir>"
			} else {
				sz = formatBytes(uint64(inf.Size()))
			}
		}
		out = append(out, fmt.Sprintf("%s  %s  %s", mode, sz, nm))
	}
	return out
}

func collectCurrentWiFiBSSID(defaultIface string) string {
	if defaultIface == "" || runtime.GOOS != "linux" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nmcli", "-t", "-g", "wifi.bssid", "device", "show", defaultIface)
	b, err := cmd.Output()
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if s == "" || strings.EqualFold(s, "--") {
		return ""
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.EqualFold(line, "--") {
			return line
		}
	}
	return ""
}

func collectBluetoothDeviceLines() []string {
	if runtime.GOOS != "linux" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bluetoothctl", "devices")
	b, err := cmd.Output()
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Device ") {
			out = append(out, strings.TrimPrefix(line, "Device "))
		}
		if len(out) >= 18 {
			break
		}
	}
	return out
}

func collectAudioDeviceLines() []string {
	if runtime.GOOS != "linux" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", "pactl list short sinks 2>/dev/null || pw-cli -m info 0 2>/dev/null | head -n 1")
	b, err := cmd.Output()
	if err != nil || len(b) == 0 {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
		if len(lines) >= 12 {
			break
		}
	}
	return lines
}

func collectMonitorLines() []string {
	if runtime.GOOS != "linux" {
		return nil
	}
	disp := strings.TrimSpace(os.Getenv("DISPLAY"))
	if disp == "" {
		disp = ":0"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "xrandr", "--listmonitors")
	cmd.Env = append(os.Environ(), "DISPLAY="+disp)
	b, err := cmd.Output()
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, line)
		if len(out) >= 12 {
			break
		}
	}
	return out
}

func collectLoadedModules() []string {
	if runtime.GOOS != "linux" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", "lsmod | awk 'NR>1{print $1}' | head -n 28")
	b, err := cmd.Output()
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func collectListenPorts() []string {
	var out []string
	switch runtime.GOOS {
	case "linux":
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "sh", "-c", "ss -tulpen 2>/dev/null | head -n 45 || ss -tuln 2>/dev/null | head -n 45")
		b, err := cmd.Output()
		if err != nil {
			return nil
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				out = append(out, line)
			}
		}
	case "darwin":
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "sh", "-c", "lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | head -n 40")
		b, err := cmd.Output()
		if err != nil {
			return nil
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				out = append(out, line)
			}
		}
	default:
		return nil
	}
	sort.Strings(out)
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

func collectDBLikeProcesses() []string {
	pids, err := process.Pids()
	if err != nil {
		return nil
	}
	keys := []string{"mariad", "mysql", "postgres", "mongod", "redis", "sqlserv", "mssql", "cockroach", "clickhouse", "influxd"}
	var hits []string
	for _, pid := range pids {
		if len(hits) >= 22 {
			break
		}
		p, err := process.NewProcess(pid)
		if err != nil {
			continue
		}
		name, err := p.Name()
		if err != nil {
			continue
		}
		nl := strings.ToLower(name)
		match := false
		for _, k := range keys {
			if strings.Contains(nl, k) {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		cmdline, _ := p.Cmdline()
		cmdline = strings.TrimSpace(cmdline)
		if len(cmdline) > 100 {
			cmdline = cmdline[:97] + "..."
		}
		hits = append(hits, fmt.Sprintf("%d · %s · %s", pid, name, cmdline))
	}
	return hits
}

func fillReportExtras(r *SystemReport) {
	r.WiFiSecurityNote = "Wi‑Fi passphrase is never exported (security policy). Manage secrets in the OS connection editor / keyring."
	r.WiFiBSSIDCurrent = strings.TrimSpace(resolveWiFiBSSID(r))
	r.BluetoothDevices = collectBluetoothDeviceLines()
	r.AudioDevices = collectAudioDeviceLines()
	r.Monitors = collectMonitorLines()
	r.LoadedModules = collectLoadedModules()
	r.ListenPorts = collectListenPorts()
	r.DBLikeProcesses = collectDBLikeProcesses()
	home := strings.TrimSpace(r.HomeDirForReport)
	if home != "" && runtime.GOOS != "windows" {
		r.HomeTopDirs, r.HomeLargestLine = collectHomeDiskUsage(home)
		r.HomeListing = collectHomeListing(home)
	}
}
