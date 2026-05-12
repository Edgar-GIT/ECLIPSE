package pcutilities

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/mem"
	psnet "github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
)

func CollectSystemReport() (*SystemReport, error) {
	r := &SystemReport{CollectedAt: time.Now()}
	h, err := host.Info()
	if err != nil {
		return nil, err
	}
	r.Hostname = h.Hostname
	r.OS = h.OS
	r.Platform = h.Platform
	r.OSVersion = h.PlatformVersion
	r.Kernel = h.KernelVersion
	r.GoArch = runtime.GOARCH
	r.KernelArch = h.KernelArch
	r.HostID = h.HostID
	if h.VirtualizationSystem != "" || h.VirtualizationRole != "" {
		r.Virtual = strings.TrimSpace(h.VirtualizationSystem + " " + h.VirtualizationRole)
	}
	if h.Uptime > 0 {
		r.Uptime = formatDuration(time.Duration(h.Uptime) * time.Second)
	}
	if h.BootTime > 0 {
		r.BootTime = time.Unix(int64(h.BootTime), 0).Format(time.RFC3339)
	}
	r.ProcCount = uint64(h.Procs)

	if users, err := host.Users(); err == nil {
		seen := map[string]struct{}{}
		var names []string
		for _, u := range users {
			u.User = strings.TrimSpace(u.User)
			if u.User == "" {
				continue
			}
			if _, ok := seen[u.User]; ok {
				continue
			}
			seen[u.User] = struct{}{}
			names = append(names, u.User)
		}
		sort.Strings(names)
		r.UserNames = strings.Join(names, ", ")
	}

	if temps, err := host.SensorsTemperatures(); err == nil {
		counts := map[string]int{}
		for _, t := range temps {
			if t.Temperature == 0 {
				continue
			}
			label := strings.TrimSpace(t.SensorKey)
			if label == "" {
				label = t.String()
			}
			counts[label]++
			if c := counts[label]; c > 1 {
				label = fmt.Sprintf("%s · %d", label, c)
			}
			r.Thermal = append(r.Thermal, struct {
				Label string
				TempC float64
			}{label, t.Temperature})
		}
	}

	if infos, err := cpu.Info(); err == nil && len(infos) > 0 {
		r.CPUModel = infos[0].ModelName
		r.CPUMhz = fmt.Sprintf("%.0f", infos[0].Mhz)
	}
	if n, err := cpu.Counts(false); err == nil {
		r.CPUPhysical = n
	}
	if n, err := cpu.Counts(true); err == nil {
		r.CPULogical = n
	}
	if pct, err := cpu.Percent(750*time.Millisecond, false); err == nil && len(pct) > 0 {
		var sum float64
		for _, p := range pct {
			sum += p
		}
		r.CPUUsagePct = sum / float64(len(pct))
	}
	if runtime.GOOS != "windows" {
		if avg, err := load.Avg(); err == nil {
			r.LoadAvg = fmt.Sprintf("%.2f / %.2f / %.2f", avg.Load1, avg.Load5, avg.Load15)
		}
	}

	if vm, err := mem.VirtualMemory(); err == nil {
		r.RAMTotal = vm.Total
		r.RAMUsed = vm.Used
		r.RAMAvail = vm.Available
		r.RAMUsedPct = vm.UsedPercent
	}
	if sm, err := mem.SwapMemory(); err == nil {
		r.SwapTotal = sm.Total
		r.SwapUsed = sm.Used
		r.SwapUsedPct = sm.UsedPercent
	}

	parts, err := disk.Partitions(false)
	if err == nil {
		seen := map[string]struct{}{}
		for _, p := range parts {
			mp := strings.TrimSpace(p.Mountpoint)
			if mp == "" {
				continue
			}
			if _, dup := seen[mp]; dup {
				continue
			}
			usage, uerr := disk.Usage(mp)
			if uerr != nil {
				continue
			}
			seen[mp] = struct{}{}
			pct := usage.UsedPercent
			if pct == 0 && usage.Total > 0 {
				pct = float64(usage.Used) * 100 / float64(usage.Total)
			}
			dv := DiskVol{
				Mountpoint: mp,
				Device:     p.Device,
				Fstype:     usage.Fstype,
				Total:      usage.Total,
				Used:       usage.Used,
				Free:       usage.Free,
				UsedPct:    pct,
				Medium:     mediumForDevice(p.Device),
			}
			r.Disks = append(r.Disks, dv)
			r.DiskTotalBytes += usage.Total
			r.DiskFreeBytes += usage.Free
			r.DiskUsedBytes += usage.Used
		}
	}

	if ifs, err := psnet.Interfaces(); err == nil {
		sort.Slice(ifs, func(i, j int) bool { return ifs[i].Name < ifs[j].Name })
		for _, iface := range ifs {
			if iface.Name == "" || isLoopbackName(iface.Name) {
				continue
			}
			addrs := make([]string, 0, len(iface.Addrs))
			for _, a := range iface.Addrs {
				if strings.TrimSpace(a.Addr) != "" {
					addrs = append(addrs, a.Addr)
				}
			}
			if len(addrs) == 0 {
				continue
			}
			wifi := ifaceNameLooksWifi(iface.Name)
			if runtime.GOOS == "windows" && strings.Contains(strings.ToLower(iface.Name), "wi-fi") {
				wifi = true
			}
			r.InterfaceRows = append(r.InterfaceRows, NetIface{
				Name:     iface.Name,
				Hardware: strings.TrimSpace(strings.ToUpper(iface.HardwareAddr)),
				Addrs:    addrs,
				IsWifi:   wifi,
			})
			for _, a := range addrs {
				ip := strings.Split(a, "/")[0]
				if strings.HasPrefix(ip, "127.") || strings.EqualFold(ip, "::1") {
					continue
				}
				r.LocalIPs = append(r.LocalIPs, ip)
			}
		}
	}

	if io, err := psnet.IOCounters(false); err == nil {
		sort.Slice(io, func(i, j int) bool { return io[i].Name < io[j].Name })
		for _, c := range io {
			if strings.HasPrefix(c.Name, "lo") || c.Name == "Loopback Pseudo-Interface 1" {
				continue
			}
			r.NetIO = append(r.NetIO, struct {
				Name string
				Rx   uint64
				Tx   uint64
				PRx  uint64
				PTx  uint64
			}{c.Name, c.BytesRecv, c.BytesSent, c.PacketsRecv, c.PacketsSent})
		}
	}

	r.PID = os.Getpid()
	r.GoVersion = runtime.Version()
	r.Goroutines = runtime.NumGoroutine()
	if pids, err := process.Pids(); err == nil {
		r.ProcVis = len(pids)
	}

	r.GPUNames = collectGPUNames()
	r.DefaultIface, r.ActiveConn = collectActiveConnection(r.InterfaceRows)
	r.WiFiNetworks = collectWiFiList()
	markActiveWiFi(&r.WiFiNetworks, r.ActiveConn)
	r.PublicIP, r.PublicIPErr = fetchPublicIP()
	r.HomeDirForReport = reportHomeDir()
	r.NetDownMbps, r.NetUpMbps = collectNetMbps(r.DefaultIface)
	fillReportExtras(r)

	return r, nil
}

func ifaceNameLooksWifi(name string) bool {
	lower := strings.ToLower(name)
	for _, sub := range []string{"wlan", "wlp", "wifi", "wi-fi"} {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

func isLoopbackName(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "loopback") || n == "lo"
}

func mediumForDevice(dev string) string {
	if runtime.GOOS != "linux" || dev == "" {
		return "—"
	}
	pkout, err := exec.Command("lsblk", "-n", "-o", "PKNAME", dev).Output()
	pk := strings.TrimSpace(string(pkout))
	if pk == "" {
		pk = strings.TrimPrefix(filepath.Base(dev), "/dev/")
	}
	if pk == "" {
		return "—"
	}
	b, err := os.ReadFile(filepath.Join("/sys/block", pk, "queue", "rotational"))
	if err != nil {
		return "—"
	}
	if strings.TrimSpace(string(b)) == "0" {
		return "SSD"
	}
	if strings.TrimSpace(string(b)) == "1" {
		return "HDD"
	}
	return "—"
}

func collectGPUNames() []string {
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("sh", "-c", "lspci 2>/dev/null | grep -iE 'vga|3d|display'").Output()
		if err == nil && len(out) > 0 {
			var lines []string
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					if idx := strings.Index(line, ": "); idx >= 0 {
						line = strings.TrimSpace(line[idx+2:])
					}
					lines = append(lines, line)
				}
			}
			if len(lines) > 0 {
				return lines
			}
		}
	case "windows":
		out, err := exec.Command("powershell", "-NoProfile", "-Command",
			"Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name").Output()
		if err == nil {
			var lines []string
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					lines = append(lines, line)
				}
			}
			if len(lines) > 0 {
				return lines
			}
		}
	case "darwin":
		out, err := exec.Command("system_profiler", "SPDisplaysDataType").Output()
		if err == nil {
			var lines []string
			sc := bufio.NewScanner(strings.NewReader(string(out)))
			for sc.Scan() {
				t := strings.TrimSpace(sc.Text())
				if strings.HasPrefix(t, "Chipset Model:") {
					lines = append(lines, strings.TrimSpace(strings.TrimPrefix(t, "Chipset Model:")))
				}
			}
			if len(lines) > 0 {
				return lines
			}
		}
	}
	return nil
}

func collectActiveConnection(ifaces []NetIface) (defaultIface string, summary string) {
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status").Output()
		if err == nil {
			sc := bufio.NewScanner(strings.NewReader(string(out)))
			for sc.Scan() {
				parts := strings.Split(sc.Text(), ":")
				if len(parts) < 4 {
					continue
				}
				dev, typ, state, conn := parts[0], parts[1], parts[2], parts[3]
				if !strings.EqualFold(strings.TrimSpace(state), "connected") {
					continue
				}
				conn = strings.TrimSpace(conn)
				typ = strings.TrimSpace(typ)
				dev = strings.TrimSpace(dev)
				if conn == "" || conn == "--" {
					continue
				}
				defaultIface = dev
				if strings.EqualFold(typ, "wifi") || strings.EqualFold(typ, "802-11-wireless") {
					return dev, fmt.Sprintf("Wi‑Fi · %s · %s", conn, dev)
				}
				return dev, fmt.Sprintf("Ethernet · %s · %s", conn, dev)
			}
		}
		out2, err2 := exec.Command("iwgetid", "-r").Output()
		if err2 == nil {
			ssid := strings.TrimSpace(string(out2))
			if ssid != "" {
				return "", fmt.Sprintf("Wi‑Fi · %s", ssid)
			}
		}
	case "windows":
		out, err := exec.Command("powershell", "-NoProfile", "-Command",
			"(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1).InterfaceAlias").Output()
		if err == nil {
			iface := strings.TrimSpace(string(out))
			if iface != "" {
				defaultIface = iface
			}
		}
		outW, err := exec.Command("netsh", "wlan", "show", "interfaces").Output()
		if err == nil {
			var ssid, state string
			for _, line := range strings.Split(string(outW), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(strings.ToLower(line), "state") && strings.Contains(line, ":") {
					state = strings.TrimSpace(line[strings.Index(line, ":")+1:])
				}
				if strings.HasPrefix(strings.ToLower(line), "ssid") && strings.Contains(line, ":") {
					v := strings.TrimSpace(line[strings.Index(line, ":")+1:])
					if !strings.EqualFold(v, "bssid") {
						ssid = v
					}
				}
			}
			if strings.EqualFold(state, "connected") && ssid != "" {
				if defaultIface != "" {
					return defaultIface, fmt.Sprintf("Wi‑Fi · %s · %s", ssid, defaultIface)
				}
				return defaultIface, fmt.Sprintf("Wi‑Fi · %s", ssid)
			}
		}
		if defaultIface != "" {
			return defaultIface, fmt.Sprintf("Ethernet / routed · %s", defaultIface)
		}
	case "darwin":
		out, err := exec.Command("route", "-n", "get", "default").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "interface:") {
					defaultIface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
					break
				}
			}
		}
		out2, err := exec.Command("networksetup", "-getairportnetwork", "en0").Output()
		if err == nil && strings.Contains(string(out2), ":") {
			p := strings.TrimSpace(strings.SplitN(string(out2), ":", 2)[1])
			if p != "" && !strings.Contains(strings.ToLower(p), "not associated") {
				return defaultIface, fmt.Sprintf("Wi‑Fi · %s", p)
			}
		}
		if defaultIface != "" {
			return defaultIface, fmt.Sprintf("Active · %s", defaultIface)
		}
	}
	if len(ifaces) > 0 {
		return ifaces[0].Name, fmt.Sprintf("%s · %s", ifaces[0].Name, strings.Join(ifaces[0].Addrs, ", "))
	}
	return "", "—"
}

func collectWiFiList() []WiFiNet {
	var out []WiFiNet
	switch runtime.GOOS {
	case "linux":
		tryTab := func() ([]byte, error) {
			return exec.Command("nmcli", "--separator", "\t", "-f", "SSID,SIGNAL,SECURITY,ACTIVE,BSSID", "dev", "wifi", "list", "--rescan", "no").Output()
		}
		b, err := tryTab()
		if err != nil {
			b, err = exec.Command("nmcli", "--separator", "\t", "-f", "SSID,SIGNAL,SECURITY,ACTIVE,BSSID", "dev", "wifi").Output()
		}
		if err == nil && len(b) > 0 && bytes.Contains(b, []byte("\t")) {
			best := map[string]WiFiNet{}
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				parts := strings.Split(line, "\t")
				for len(parts) < 5 {
					parts = append(parts, "")
				}
				ssid, sig, sec, act, bssid := parts[0], parts[1], parts[2], parts[3], parts[4]
				if ssid == "" || ssid == "--" {
					continue
				}
				cand := WiFiNet{
					SSID:     ssid,
					BSSID:    strings.TrimSpace(bssid),
					Signal:   strings.TrimSpace(sig) + "%",
					Security: strings.TrimSpace(sec),
					Active:   strings.EqualFold(strings.TrimSpace(act), "yes"),
				}
				prev, ok := best[ssid]
				if !ok || wifiSignalStrength(cand.Signal) > wifiSignalStrength(prev.Signal) {
					best[ssid] = cand
				}
			}
			for _, w := range best {
				out = append(out, w)
			}
		} else {
			cmd := exec.Command("nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY,ACTIVE", "dev", "wifi", "list", "--rescan", "no")
			b2, err2 := cmd.Output()
			if err2 != nil {
				cmd2 := exec.Command("nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY,ACTIVE", "dev", "wifi")
				b2, err2 = cmd2.Output()
			}
			if err2 != nil {
				return out
			}
			seen := map[string]struct{}{}
			for _, line := range strings.Split(string(b2), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				parts := strings.Split(line, ":")
				for len(parts) < 4 {
					parts = append(parts, "")
				}
				ssid, sig, sec, act := parts[0], parts[1], parts[2], parts[3]
				if ssid == "" || ssid == "--" {
					continue
				}
				key := ssid + "|" + sig
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, WiFiNet{
					SSID:     ssid,
					Signal:   sig + "%",
					Security: sec,
					Active:   strings.EqualFold(act, "yes"),
				})
			}
		}
	case "windows":
		b, err := exec.Command("netsh", "wlan", "show", "networks", "mode=Bssid").Output()
		if err != nil {
			return out
		}
		var curSSID string
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "SSID ") && strings.Contains(line, ":") {
				curSSID = strings.TrimSpace(line[strings.Index(line, ":")+1:])
				continue
			}
			if strings.HasPrefix(line, "Signal") && strings.Contains(line, ":") && curSSID != "" {
				sig := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line[strings.Index(line, ":")+1:]), "%"))
				out = append(out, WiFiNet{SSID: curSSID, Signal: sig + "%", Security: "—", Active: false})
				curSSID = ""
			}
		}
	case "darwin":
		b, err := exec.Command("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s").Output()
		if err != nil {
			return out
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "SSID") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			out = append(out, WiFiNet{SSID: fields[0], Signal: fields[1] + "%", Security: "—", Active: false})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SSID < out[j].SSID })
	return out
}

func wifiSignalStrength(sig string) int {
	sig = strings.TrimSpace(strings.TrimSuffix(sig, "%"))
	n, _ := strconv.Atoi(sig)
	return n
}

func markActiveWiFi(nets *[]WiFiNet, activeSummary string) {
	if nets == nil || len(*nets) == 0 {
		return
	}
	low := strings.ToLower(activeSummary)
	for i := range *nets {
		ssid := (*nets)[i].SSID
		if ssid != "" && strings.Contains(low, strings.ToLower(ssid)) {
			(*nets)[i].Active = true
		}
	}
}

func fetchPublicIP() (string, string) {
	client := &http.Client{Timeout: 6 * time.Second}
	urls := []string{
		"https://api.ipify.org?format=text",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}
	var lastErr string
	for _, u := range urls {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		req.Header.Set("User-Agent", "ECLIPSE-pcutilities/1.0")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		if err != nil {
			lastErr = err.Error()
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = "http " + strconv.Itoa(resp.StatusCode)
			continue
		}
		s := strings.TrimSpace(string(body))
		if s != "" {
			return s, ""
		}
		lastErr = "empty"
	}
	if lastErr == "" {
		lastErr = "unavailable"
	}
	return "", lastErr
}

func pickIOCounters(list []psnet.IOCountersStat, name string) (psnet.IOCountersStat, bool) {
	for _, c := range list {
		if c.Name == name {
			return c, true
		}
	}
	return psnet.IOCountersStat{}, false
}

func collectNetMbps(defaultIface string) (down float64, up float64) {
	c1, err := psnet.IOCounters(false)
	if err != nil || len(c1) == 0 {
		return 0, 0
	}
	time.Sleep(time.Second)
	c2, err2 := psnet.IOCounters(false)
	if err2 != nil {
		return 0, 0
	}
	m1 := map[string]psnet.IOCountersStat{}
	for _, c := range c1 {
		m1[c.Name] = c
	}
	const sec = 1.0
	var drx, dtx uint64
	iface := strings.TrimSpace(defaultIface)
	if iface != "" {
		a, ok1 := m1[iface]
		b, ok2 := pickIOCounters(c2, iface)
		if ok1 && ok2 {
			if b.BytesRecv >= a.BytesRecv {
				drx = b.BytesRecv - a.BytesRecv
			}
			if b.BytesSent >= a.BytesSent {
				dtx = b.BytesSent - a.BytesSent
			}
		}
	} else {
		for _, b := range c2 {
			if strings.HasPrefix(b.Name, "lo") || b.Name == "Loopback Pseudo-Interface 1" {
				continue
			}
			a, ok := m1[b.Name]
			if !ok {
				continue
			}
			if b.BytesRecv >= a.BytesRecv {
				drx += b.BytesRecv - a.BytesRecv
			}
			if b.BytesSent >= a.BytesSent {
				dtx += b.BytesSent - a.BytesSent
			}
		}
	}
	return float64(drx) * 8 / 1e6 / sec, float64(dtx) * 8 / 1e6 / sec
}
