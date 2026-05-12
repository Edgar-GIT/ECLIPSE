package pcutilities

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/process"
)

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
	return s
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

func collectHomeDiskUsage() (lines []string, largest string) {
	home := strings.TrimSpace(os.Getenv("HOME"))
	if home == "" || runtime.GOOS == "windows" {
		return nil, ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	// Summarize top-level dirs under $HOME (can be slow on huge trees).
	cmd := exec.CommandContext(ctx, "sh", "-c",
		fmt.Sprintf("du -xh --max-depth=1 %q 2>/dev/null | sort -hr | head -n 18", home))
	b, err := cmd.Output()
	if err != nil {
		return nil, ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) > 1 {
		// First line is usually $HOME itself; second is often largest child.
		for _, ln := range lines[1:] {
			if strings.HasPrefix(ln, home+string(filepath.Separator)) || strings.Contains(ln, "\t") {
				largest = ln
				break
			}
		}
	}
	if largest == "" && len(lines) > 0 {
		largest = lines[0]
	}
	return lines, largest
}

func fillReportExtras(r *SystemReport) {
	r.WiFiSecurityNote = "Wi‑Fi passphrase is never exported (security policy). Manage secrets in the OS connection editor / keyring."
	r.WiFiBSSIDCurrent = collectCurrentWiFiBSSID(r.DefaultIface)
	r.BluetoothDevices = collectBluetoothDeviceLines()
	r.AudioDevices = collectAudioDeviceLines()
	r.Monitors = collectMonitorLines()
	r.LoadedModules = collectLoadedModules()
	r.ListenPorts = collectListenPorts()
	r.DBLikeProcesses = collectDBLikeProcesses()
	r.HomeTopDirs, r.HomeLargestLine = collectHomeDiskUsage()
}
