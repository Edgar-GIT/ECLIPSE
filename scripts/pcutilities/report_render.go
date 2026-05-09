package pcutilities

import (
	"fmt"
	"strings"
	"time"

	"programa/utils"
)

const tableWidth = 76

func gradientTitle(s string, useColor bool) string {
	if !useColor {
		return s
	}
	if s == "" {
		return s
	}
	var b strings.Builder
	n := len([]rune(s))
	rs := []rune(s)
	for i, ch := range rs {
		t := 0.0
		if n > 1 {
			t = float64(i) / float64(n-1)
		}
		r := lerp(90, 255, t)
		g := lerp(140, 90, t)
		bl := lerp(255, 180, t)
		b.WriteString(utils.RGBText(r, g, bl, string(ch)))
	}
	return b.String()
}

func lerp(a, b int, t float64) int {
	return int(float64(a) + (float64(b-a))*t)
}

func rgbBarPct(pct float64, width int, useColor bool) string {
	if width < 8 {
		width = 8
	}
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := int(pct / 100 * float64(width))
	if pct > 0 && filled == 0 {
		filled = 1
	}
	var b strings.Builder
	for i := 0; i < width; i++ {
		if i < filled {
			t := float64(i+1) / float64(filled)
			if filled == 0 {
				t = 0
			}
			r, g, bl := barRGB(pct, t)
			if useColor {
				b.WriteString(utils.RGBText(r, g, bl, "█"))
			} else {
				b.WriteRune('#')
			}
		} else {
			if useColor {
				b.WriteString(utils.RGBText(45, 48, 62, "░"))
			} else {
				b.WriteRune('.')
			}
		}
	}
	suffix := fmt.Sprintf(" %.1f%%", pct)
	if useColor {
		return b.String() + utils.RGBText(200, 200, 220, suffix)
	}
	return b.String() + suffix
}

func barRGB(globalPct, segT float64) (int, int, int) {
	u := (globalPct*0.6 + segT*40) / 100
	if u > 1 {
		u = 1
	}
	r := lerp(60, 255, u)
	g := lerp(220, 70, u)
	bl := lerp(120, 90, u)
	return r, g, bl
}

func boxTop(title string, useColor bool) string {
	line := strings.Repeat("═", tableWidth-2)
	inner := tableWidth - 6
	tit := truncateRunes(title, inner)
	pad := inner - len([]rune(tit))
	if pad < 0 {
		pad = 0
	}
	if useColor {
		return fmt.Sprintf("  ╔%s╗\n  ║ %s%s ║", line, gradientTitle(tit, true), strings.Repeat(" ", pad))
	}
	return fmt.Sprintf("  ╔%s╗\n  ║ %s%s ║", line, tit, strings.Repeat(" ", pad))
}

func boxSep(useColor bool) string {
	line := strings.Repeat("═", tableWidth-2)
	if useColor {
		return utils.RGBText(70, 100, 160, "  ╠"+line+"╣")
	}
	return "  +" + strings.Repeat("=", tableWidth-2) + "+"
}

func boxBottom(useColor bool) string {
	line := strings.Repeat("═", tableWidth-2)
	if useColor {
		return utils.RGBText(70, 100, 160, "  ╚"+line+"╝")
	}
	return "  +" + strings.Repeat("=", tableWidth-2) + "+"
}

func row2(k, v string, useColor bool) string {
	k = strings.TrimSpace(k)
	v = strings.TrimSpace(v)
	if v == "" {
		v = "—"
	}
	kw := 22
	vw := tableWidth - 8 - kw
	ks := truncateRunes(k, kw)
	vs := truncateRunes(v, vw)
	if useColor {
		return fmt.Sprintf("  ║ %s%s ║ %s%s ║",
			utils.Yellow+ks+utils.Reset,
			strings.Repeat(" ", kw-len([]rune(ks))),
			vs,
			strings.Repeat(" ", vw-len([]rune(vs))))
	}
	return fmt.Sprintf("  | %-*s | %-*s |", kw, ks, vw, vs)
}

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 3 {
		return string(r[:max])
	}
	return string(r[:max-3]) + "..."
}

func tableKeyValue(title string, rows [][2]string, useColor bool) string {
	var b strings.Builder
	b.WriteString(boxTop(title, useColor))
	b.WriteByte('\n')
	for i, row := range rows {
		b.WriteString(row2(row[0], row[1], useColor))
		b.WriteByte('\n')
		if i < len(rows)-1 {
			mid := strings.Repeat("─", tableWidth-2)
			if useColor {
				b.WriteString("  ╟" + mid + "╢\n")
			} else {
				b.WriteString("  |" + strings.Repeat("-", tableWidth-2) + "|\n")
			}
		}
	}
	b.WriteString(boxBottom(useColor))
	b.WriteByte('\n')
	return b.String()
}

func tableMultiHeader(title string, headers []string, rows [][]string, useColor bool) string {
	if len(headers) == 0 {
		return ""
	}
	n := len(headers)
	sepChars := 0
	if n > 1 {
		sepChars = (n - 1) * 3
	}
	avail := tableWidth - 6 - sepChars
	if avail < n*4 {
		avail = n * 4
	}
	colW := avail / n
	var b strings.Builder
	b.WriteString(boxTop(title, useColor))
	b.WriteByte('\n')
	b.WriteString("  ║ ")
	for i, h := range headers {
		hs := truncateRunes(h, colW)
		if useColor {
			b.WriteString(utils.Purple + hs + utils.Reset)
		} else {
			b.WriteString(hs)
		}
		b.WriteString(strings.Repeat(" ", colW-len([]rune(hs))))
		if i < n-1 {
			b.WriteString(" │ ")
		}
	}
	b.WriteString(" ║\n")
	mid := strings.Repeat("─", tableWidth-2)
	if useColor {
		b.WriteString("  ╟" + mid + "╢\n")
	} else {
		b.WriteString("  |" + strings.Repeat("-", tableWidth-2) + "|\n")
	}
	for _, row := range rows {
		b.WriteString("  ║ ")
		for i := 0; i < n; i++ {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			cs := truncateRunes(strings.TrimSpace(cell), colW)
			b.WriteString(cs)
			b.WriteString(strings.Repeat(" ", colW-len([]rune(cs))))
			if i < n-1 {
				b.WriteString(" │ ")
			}
		}
		b.WriteString(" ║\n")
	}
	b.WriteString(boxBottom(useColor))
	b.WriteByte('\n')
	return b.String()
}

func RenderReportText(r *SystemReport, useColor bool) string {
	var o strings.Builder
	ts := r.CollectedAt.Format("2006-01-02 15:04:05")
	head := fmt.Sprintf("ECLIPSE · System report · %s", ts)
	o.WriteString("\n")
	if useColor {
		o.WriteString(gradientTitle(head, true))
	} else {
		o.WriteString(head)
	}
	o.WriteString("\n\n")

	var hostRows [][2]string
	hostRows = append(hostRows, [2]string{"Hostname", r.Hostname})
	hostRows = append(hostRows, [2]string{"OS", r.OS})
	hostRows = append(hostRows, [2]string{"Platform", r.Platform})
	hostRows = append(hostRows, [2]string{"OS version", r.OSVersion})
	hostRows = append(hostRows, [2]string{"Kernel", r.Kernel})
	hostRows = append(hostRows, [2]string{"Architecture (Go)", r.GoArch})
	if r.KernelArch != "" {
		hostRows = append(hostRows, [2]string{"Architecture (OS)", r.KernelArch})
	}
	if r.HostID != "" {
		hostRows = append(hostRows, [2]string{"Host ID", r.HostID})
	}
	if r.Virtual != "" {
		hostRows = append(hostRows, [2]string{"Virtualization", r.Virtual})
	}
	if r.Uptime != "" {
		hostRows = append(hostRows, [2]string{"Uptime", r.Uptime})
	}
	if r.BootTime != "" {
		hostRows = append(hostRows, [2]string{"Boot time", r.BootTime})
	}
	hostRows = append(hostRows, [2]string{"Kernel processes", fmt.Sprintf("%d", r.ProcCount)})
	if r.UserNames != "" {
		hostRows = append(hostRows, [2]string{"Logged-in users", r.UserNames})
	}
	o.WriteString(tableKeyValue("Host & session", hostRows, useColor))
	o.WriteString("\n")

	var netRows [][2]string
	if len(r.LocalIPs) > 0 {
		netRows = append(netRows, [2]string{"Local IPv4/6 (list)", strings.Join(dedupeKeepOrder(r.LocalIPs), ", ")})
	}
	if r.PublicIP != "" {
		netRows = append(netRows, [2]string{"Public IP (WAN)", r.PublicIP})
	} else if r.PublicIPErr != "" {
		netRows = append(netRows, [2]string{"Public IP", "(unavailable: " + r.PublicIPErr + ")"})
	}
	netRows = append(netRows, [2]string{"Default / routed iface", nz(r.DefaultIface)})
	netRows = append(netRows, [2]string{"Active connection", nz(r.ActiveConn)})
	o.WriteString(tableKeyValue("Network summary", netRows, useColor))
	o.WriteString("\n")

	if len(r.InterfaceRows) > 0 {
		var rows [][]string
		for _, iface := range r.InterfaceRows {
			typ := "Ethernet / other"
			if iface.IsWifi {
				typ = "Wi‑Fi"
			}
			rows = append(rows, []string{iface.Name, typ, strings.Join(iface.Addrs, ", ")})
		}
		o.WriteString(tableMultiHeader("Interfaces", []string{"Name", "Type", "Addresses"}, rows, useColor))
		o.WriteString("\n")
	}

	if len(r.WiFiNetworks) > 0 {
		var rows [][]string
		for _, w := range r.WiFiNetworks {
			act := "no"
			if w.Active {
				act = "yes"
			}
			rows = append(rows, []string{w.SSID, w.Signal, w.Security, act})
		}
		o.WriteString(tableMultiHeader("Wi‑Fi networks (scan)", []string{"SSID", "Signal", "Security", "Active"}, rows, useColor))
		o.WriteString("\n")
	}

	var cpuRows [][2]string
	cpuRows = append(cpuRows, [2]string{"Model", r.CPUModel})
	cpuRows = append(cpuRows, [2]string{"Clock (reported)", r.CPUMhz + " MHz"})
	cpuRows = append(cpuRows, [2]string{"Physical cores", fmt.Sprintf("%d", r.CPUPhysical)})
	cpuRows = append(cpuRows, [2]string{"Logical threads", fmt.Sprintf("%d", r.CPULogical)})
	cpuRows = append(cpuRows, [2]string{"Usage (sampled)", fmt.Sprintf("%.1f%%", r.CPUUsagePct)})
	if r.LoadAvg != "" {
		cpuRows = append(cpuRows, [2]string{"Load avg 1/5/15", r.LoadAvg})
	}
	o.WriteString(tableKeyValue("Processor (CPU)", cpuRows, useColor))
	o.WriteString("\n")
	barW := tableWidth - 20
	if useColor {
		o.WriteString("  " + utils.RGBText(140, 180, 255, "CPU load bar: ") + rgbBarPct(r.CPUUsagePct, barW, useColor) + "\n\n")
	} else {
		o.WriteString("  CPU load bar: " + rgbBarPct(r.CPUUsagePct, barW, false) + "\n\n")
	}

	gpuList := r.GPUNames
	if len(gpuList) == 0 {
		gpuList = []string{"(no GPU detected via OS query)"}
	}
	var gpuRows [][2]string
	for i, g := range gpuList {
		gpuRows = append(gpuRows, [2]string{fmt.Sprintf("GPU #%d", i+1), g})
	}
	o.WriteString(tableKeyValue("Graphics (GPU)", gpuRows, useColor))
	o.WriteString("\n")

	var memRows [][2]string
	memRows = append(memRows, [2]string{"RAM total", formatBytes(r.RAMTotal)})
	memRows = append(memRows, [2]string{"RAM used", formatBytes(r.RAMUsed)})
	memRows = append(memRows, [2]string{"RAM available", formatBytes(r.RAMAvail)})
	memRows = append(memRows, [2]string{"RAM used %", fmt.Sprintf("%.1f%%", r.RAMUsedPct)})
	if r.SwapTotal > 0 {
		memRows = append(memRows, [2]string{"Swap total", formatBytes(r.SwapTotal)})
		memRows = append(memRows, [2]string{"Swap used", formatBytes(r.SwapUsed)})
		memRows = append(memRows, [2]string{"Swap used %", fmt.Sprintf("%.1f%%", r.SwapUsedPct)})
	}
	o.WriteString(tableKeyValue("Memory (RAM)", memRows, useColor))
	o.WriteString("\n")
	if useColor {
		o.WriteString("  " + utils.RGBText(140, 180, 255, "RAM usage bar: ") + rgbBarPct(r.RAMUsedPct, barW, useColor) + "\n\n")
	} else {
		o.WriteString("  RAM usage bar: " + rgbBarPct(r.RAMUsedPct, barW, false) + "\n\n")
	}

	var storRows [][2]string
	storRows = append(storRows, [2]string{"Aggregate capacity", formatBytes(r.DiskTotalBytes)})
	storRows = append(storRows, [2]string{"Aggregate used", formatBytes(r.DiskUsedBytes)})
	storRows = append(storRows, [2]string{"Aggregate free", formatBytes(r.DiskFreeBytes)})
	pctFree := 0.0
	pctUsed := 0.0
	if r.DiskTotalBytes > 0 {
		pctUsed = float64(r.DiskUsedBytes) * 100 / float64(r.DiskTotalBytes)
		pctFree = float64(r.DiskFreeBytes) * 100 / float64(r.DiskTotalBytes)
	}
	storRows = append(storRows, [2]string{"Volume used %", fmt.Sprintf("%.1f%% (free %.1f%%)", pctUsed, pctFree)})
	o.WriteString(tableKeyValue("Storage (all mounted volumes)", storRows, useColor))
	o.WriteString("\n")
	if useColor {
		o.WriteString("  " + utils.RGBText(140, 180, 255, "Total disk used: ") + rgbBarPct(pctUsed, barW, useColor) + "\n\n")
	} else {
		o.WriteString("  Total disk used: " + rgbBarPct(pctUsed, barW, false) + "\n\n")
	}

	if len(r.Disks) > 0 {
		var rows [][]string
		for _, d := range r.Disks {
			rows = append(rows, []string{
				d.Mountpoint,
				d.Medium,
				formatBytes(d.Total),
				formatBytes(d.Used),
				formatBytes(d.Free),
				fmt.Sprintf("%.1f%%", d.UsedPct),
			})
		}
		o.WriteString(tableMultiHeader("Per-volume breakdown", []string{"Mount", "Medium", "Size", "Used", "Free", "Used%"}, rows, useColor))
		o.WriteString("\n")
		for _, d := range r.Disks {
			if useColor {
				o.WriteString(fmt.Sprintf("  %s%s%s  %s\n", utils.Green, d.Mountpoint, utils.Reset, rgbBarPct(d.UsedPct, barW, useColor)))
			} else {
				o.WriteString(fmt.Sprintf("  %s  %s\n", d.Mountpoint, rgbBarPct(d.UsedPct, barW, false)))
			}
		}
		o.WriteString("\n")
	}

	if len(r.Thermal) > 0 {
		var trows [][2]string
		for _, t := range r.Thermal {
			trows = append(trows, [2]string{t.Label, fmt.Sprintf("%.1f °C", t.TempC)})
		}
		o.WriteString(tableKeyValue("Thermal sensors", trows, useColor))
		o.WriteString("\n")
	}

	if len(r.NetIO) > 0 {
		var rows [][]string
		for _, n := range r.NetIO {
			rows = append(rows, []string{n.Name, formatBytes(n.Rx), formatBytes(n.Tx), fmt.Sprintf("%d / %d", n.PRx, n.PTx)})
		}
		o.WriteString(tableMultiHeader("Network I/O (since boot)", []string{"Iface", "RX", "TX", "Packets rx/tx"}, rows, useColor))
		o.WriteString("\n")
	}

	var runRows [][2]string
	runRows = append(runRows, [2]string{"PID", fmt.Sprintf("%d", r.PID)})
	runRows = append(runRows, [2]string{"Go runtime", r.GoVersion})
	runRows = append(runRows, [2]string{"Goroutines (this tool)", fmt.Sprintf("%d", r.Goroutines)})
	runRows = append(runRows, [2]string{"Processes visible", fmt.Sprintf("%d", r.ProcVis)})
	o.WriteString(tableKeyValue("Runtime (scanner)", runRows, useColor))

	return o.String()
}

func nz(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func dedupeKeepOrder(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func PrintAdvancedSystemReport() {
	r, err := CollectSystemReport()
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", utils.Red, err, utils.Reset)
		return
	}
	fmt.Print(RenderReportText(r, true))
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
