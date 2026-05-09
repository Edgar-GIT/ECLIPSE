package pcutilities

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"programa/utils"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/mem"
	psnet "github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
)

func PrintAdvancedSystemReport() {
	h, err := host.Info()
	if err != nil {
		fmt.Printf("%s[!] host: %v%s\n", utils.Red, err, utils.Reset)
		return
	}

	fmt.Printf("\n%s┌── Host / OS ─────────────────────────────────────────%s\n", utils.Blue, utils.Reset)
	kv("Hostname", h.Hostname)
	kv("OS", h.OS)
	kv("Platform", h.Platform)
	kv("Family", h.PlatformFamily)
	kv("Version", h.PlatformVersion)
	kv("Kernel", h.KernelVersion)
	kv("Architecture", runtime.GOARCH)
	if h.VirtualizationRole != "" || h.VirtualizationSystem != "" {
		kv("Virtualization", strings.TrimSpace(h.VirtualizationSystem+" "+h.VirtualizationRole))
	}
	if h.Uptime > 0 {
		kv("Uptime", formatDuration(time.Duration(h.Uptime)*time.Second))
	}
	if h.BootTime > 0 {
		kv("Boot time", time.Unix(int64(h.BootTime), 0).Format(time.RFC3339))
	}
	kv("Processes (kernel)", fmt.Sprintf("%d", h.Procs))
	if users, err := host.Users(); err == nil && len(users) > 0 {
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
		if len(names) > 0 {
			kv("Logged-in users", strings.Join(names, ", "))
		}
	}

	if temps, err := host.SensorsTemperatures(); err == nil {
		header := false
		for _, t := range temps {
			if t.Temperature == 0 {
				continue
			}
			if !header {
				fmt.Printf("\n%s┌── Thermal ───────────────────────────────────────────%s\n", utils.Blue, utils.Reset)
				header = true
			}
			label := strings.TrimSpace(t.SensorKey)
			if label == "" {
				label = t.String()
			}
			kv(label, fmt.Sprintf("%.1f °C", t.Temperature))
		}
	}

	fmt.Printf("\n%s┌── CPU ───────────────────────────────────────────────%s\n", utils.Blue, utils.Reset)
	if infos, err := cpu.Info(); err == nil && len(infos) > 0 {
		c0 := infos[0]
		kv("Model", c0.ModelName)
		kv("MHz (nominal)", fmt.Sprintf("%.0f", c0.Mhz))
		kv("Cores (physical)", fmt.Sprintf("%d", c0.Cores))
	}
	if n, err := cpu.Counts(false); err == nil {
		kv("CPUs physical", fmt.Sprintf("%d", n))
	}
	if n, err := cpu.Counts(true); err == nil {
		kv("CPUs logical", fmt.Sprintf("%d", n))
	}
	if pct, err := cpu.Percent(750*time.Millisecond, false); err == nil && len(pct) > 0 {
		var sum float64
		for _, p := range pct {
			sum += p
		}
		kv("CPU usage (all)", fmt.Sprintf("%.1f%%", sum/float64(len(pct))))
	}

	if runtime.GOOS != "windows" {
		if avg, err := load.Avg(); err == nil {
			kv("Load (1/5/15)", fmt.Sprintf("%.2f / %.2f / %.2f", avg.Load1, avg.Load5, avg.Load15))
		}
	}

	fmt.Printf("\n%s┌── Memory ────────────────────────────────────────────%s\n", utils.Blue, utils.Reset)
	if vm, err := mem.VirtualMemory(); err == nil {
		kv("RAM total", formatBytes(vm.Total))
		kv("RAM used", formatBytes(vm.Used))
		kv("RAM available", formatBytes(vm.Available))
		kv("RAM used %", fmt.Sprintf("%.1f%%", vm.UsedPercent))
	}
	if sm, err := mem.SwapMemory(); err == nil && sm.Total > 0 {
		kv("Swap total", formatBytes(sm.Total))
		kv("Swap used", formatBytes(sm.Used))
		kv("Swap used %", fmt.Sprintf("%.1f%%", sm.UsedPercent))
	}

	fmt.Printf("\n%s┌── Disks ─────────────────────────────────────────────%s\n", utils.Blue, utils.Reset)
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
			fmt.Printf("  %s%s%s  %s\n", utils.Green, mp, utils.Reset, utils.Reset)
			kv("    Device", p.Device)
			kv("    Fstype", usage.Fstype)
			kv("    Size", formatBytes(usage.Total))
			kv("    Used", fmt.Sprintf("%s (%.1f%%)", formatBytes(usage.Used), pct))
			kv("    Free", formatBytes(usage.Free))
		}
	}

	fmt.Printf("\n%s┌── Network interfaces ────────────────────────────────%s\n", utils.Blue, utils.Reset)
	if ifs, err := psnet.Interfaces(); err == nil {
		sort.Slice(ifs, func(i, j int) bool { return ifs[i].Name < ifs[j].Name })
		for _, iface := range ifs {
			if iface.Name == "" {
				continue
			}
			if isLoopbackIface(iface) {
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
			kv(iface.Name, strings.Join(addrs, ", "))
		}
	}

	if io, err := psnet.IOCounters(true); err == nil && len(io) > 0 {
		fmt.Printf("\n%s┌── Network I/O (since boot) ──────────────────────────%s\n", utils.Blue, utils.Reset)
		sort.Slice(io, func(i, j int) bool { return io[i].Name < io[j].Name })
		for _, c := range io {
			if strings.HasPrefix(c.Name, "lo") || c.Name == "Loopback Pseudo-Interface 1" {
				continue
			}
			fmt.Printf("  %s%s%s\n", utils.Purple, c.Name, utils.Reset)
			kv("    RX", formatBytes(c.BytesRecv))
			kv("    TX", formatBytes(c.BytesSent))
			kv("    Packets", fmt.Sprintf("rx %d / tx %d", c.PacketsRecv, c.PacketsSent))
		}
	}

	fmt.Printf("\n%s┌── Runtime / process ─────────────────────────────────%s\n", utils.Blue, utils.Reset)
	kv("PID", fmt.Sprintf("%d", os.Getpid()))
	kv("Go version", runtime.Version())
	kv("Goroutines", fmt.Sprintf("%d", runtime.NumGoroutine()))
	if pids, err := process.Pids(); err == nil {
		kv("Processes (visible)", fmt.Sprintf("%d", len(pids)))
	}

	fmt.Println()
}

func kv(k, v string) {
	v = strings.TrimSpace(v)
	if v == "" {
		v = "—"
	}
	fmt.Printf("  %s%-22s%s %s\n", utils.Yellow, k+":", utils.Reset, v)
}

func formatBytes(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	v := float64(n)
	suffix := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	i := -1
	for v >= 1024 && i < len(suffix)-1 {
		v /= 1024
		i++
	}
	return fmt.Sprintf("%.2f %s", v, suffix[i])
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	d = d.Round(time.Second)
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, h, m, s)
	}
	return fmt.Sprintf("%dh %dm %ds", h, m, s)
}

func isLoopbackIface(iface psnet.InterfaceStat) bool {
	n := strings.ToLower(iface.Name)
	if strings.Contains(n, "loopback") || n == "lo" {
		return true
	}
	for _, a := range iface.Addrs {
		if strings.HasPrefix(a.Addr, "127.") || strings.HasPrefix(strings.ToLower(a.Addr), "::1") {
			return true
		}
	}
	return false
}
