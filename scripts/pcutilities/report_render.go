package pcutilities

import (
	"fmt"
	"strings"
	"time"

	"programa/utils"
)

func clrBorder(s string) string {
	return utils.RGBText(255, 79, 216, s)
}

func clrKey(s string) string {
	return utils.RGBText(0, 245, 212, s)
}

func clrAccent(s string) string {
	return utils.RGBText(255, 214, 10, s)
}

func clrDim(s string) string {
	return utils.RGBText(185, 198, 255, s)
}

func gradientTitle(s string, useColor bool) string {
	if !useColor {
		return s
	}
	if s == "" {
		return s
	}
	var b strings.Builder
	rs := []rune(s)
	n := len(rs)
	for i, ch := range rs {
		t := 0.0
		if n > 1 {
			t = float64(i) / float64(n-1)
		}
		r := lerp(255, 80, t)
		g := lerp(100, 250, t)
		bl := lerp(200, 255, t)
		b.WriteString(utils.RGBText(r, g, bl, string(ch)))
	}
	return b.String()
}

func lerp(a, b int, t float64) int {
	return int(float64(a) + (float64(b-a))*t)
}

func rgbBarPct(pct float64, width int, useColor bool) string {
	if width < 12 {
		width = 12
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
			t := 0.0
			if filled > 0 {
				t = float64(i+1) / float64(filled)
			}
			r, g, bl := barRGB(pct, t)
			if useColor {
				b.WriteString(utils.RGBText(r, g, bl, "▓"))
			} else {
				b.WriteRune('#')
			}
		} else {
			if useColor {
				b.WriteString(utils.RGBText(38, 42, 68, "░"))
			} else {
				b.WriteRune('.')
			}
		}
	}
	suffix := fmt.Sprintf(" %.1f%%", pct)
	if useColor {
		return b.String() + clrAccent(suffix)
	}
	return b.String() + suffix
}

func barRGB(globalPct, segT float64) (int, int, int) {
	u := (globalPct*0.45 + segT*55) / 100
	if u > 1 {
		u = 1
	}
	r := lerp(20, 255, u)
	g := lerp(255, 40, u)
	bl := lerp(180, 140, u)
	return r, g, bl
}

func barLineTw(tw int, label string, pct float64, useColor bool) string {
	label = strings.TrimSpace(label)
	if label == "" {
		label = "Usage"
	}
	prefix := " " + label + " "
	barW := tw - len([]rune(prefix)) - 10
	if barW < 12 {
		barW = 12
	}
	if useColor {
		return prefix + rgbBarPct(pct, barW, true) + "\n"
	}
	return prefix + rgbBarPct(pct, barW, false) + "\n"
}

func boxTopTw(tw int, title string, useColor bool) string {
	horiz := tw - 2
	top := "╔" + strings.Repeat("═", horiz) + "╗"
	lineInner := tw - 4
	if lineInner < 8 {
		lineInner = 8
	}
	tit := truncateRunes(title, lineInner)
	pad := lineInner - len([]rune(tit))
	if pad < 0 {
		pad = 0
	}
	var titOut string
	if useColor {
		titOut = gradientTitle(tit, true)
	} else {
		titOut = tit
	}
	var line string
	if useColor {
		top = clrBorder(top)
		line = clrBorder("║") + " " + titOut + strings.Repeat(" ", pad) + " " + clrBorder("║")
	} else {
		line = fmt.Sprintf("║ %s%s ║", titOut, strings.Repeat(" ", pad))
	}
	return top + "\n" + line
}

func boxBottomTw(tw int, useColor bool) string {
	horiz := tw - 2
	s := "╚" + strings.Repeat("═", horiz) + "╝"
	if useColor {
		return clrBorder(s)
	}
	return s
}

func rowSepTw(tw int, useColor bool) string {
	mid := strings.Repeat("─", tw-2)
	s := "╟" + mid + "╢"
	if useColor {
		return clrBorder(s)
	}
	return s
}

func row2Tw(tw int, k, v string, useColor bool) string {
	k = strings.TrimSpace(k)
	v = strings.TrimSpace(v)
	if v == "" {
		v = "—"
	}
	payloadW := tw - 4
	if payloadW < 8 {
		payloadW = 8
	}
	sep := " │ "
	sepW := len([]rune(sep))
	avail := payloadW - sepW
	if avail < 4 {
		avail = 4
	}
	keyW := avail / 2
	valW := avail - keyW
	ks := truncateRunes(k, keyW)
	vs := truncateRunes(v, valW)
	padK := keyW - len([]rune(ks))
	padV := valW - len([]rune(vs))
	if padK < 0 {
		padK = 0
	}
	if padV < 0 {
		padV = 0
	}
	if useColor {
		left := clrKey(ks) + strings.Repeat(" ", padK)
		right := clrDim(vs) + strings.Repeat(" ", padV)
		return clrBorder("║") + " " + left + clrBorder(sep) + right + " " + clrBorder("║")
	}
	return "║ " + ks + strings.Repeat(" ", padK) + sep + vs + strings.Repeat(" ", padV) + " ║"
}

func tableKeyValueTw(tw int, title string, rows [][2]string, useColor bool) string {
	var b strings.Builder
	b.WriteString(boxTopTw(tw, title, useColor))
	b.WriteByte('\n')
	for i, row := range rows {
		b.WriteString(row2Tw(tw, row[0], row[1], useColor))
		b.WriteByte('\n')
		if i < len(rows)-1 {
			b.WriteString(rowSepTw(tw, useColor))
			b.WriteByte('\n')
		}
	}
	b.WriteString(boxBottomTw(tw, useColor))
	b.WriteByte('\n')
	return b.String()
}

func tableMultiHeaderTw(tw int, title string, headers []string, rows [][]string, useColor bool) string {
	if len(headers) == 0 {
		return ""
	}
	n := len(headers)
	payloadW := tw - 4
	if payloadW < n*4 {
		payloadW = n * 4
	}
	sepCell := " │ "
	sepW := len([]rune(sepCell)) * (n - 1)
	avail := payloadW - sepW
	if avail < n {
		avail = n
	}
	colW := avail / n

	var b strings.Builder
	b.WriteString(boxTopTw(tw, title, useColor))
	b.WriteByte('\n')

	headParts := make([]string, n)
	for i, h := range headers {
		hs := truncateRunes(h, colW)
		pad := colW - len([]rune(hs))
		if pad < 0 {
			pad = 0
		}
		if useColor {
			headParts[i] = clrAccent(hs) + strings.Repeat(" ", pad)
		} else {
			headParts[i] = hs + strings.Repeat(" ", pad)
		}
	}
	headLine := strings.Join(headParts, sepCell)
	if useColor {
		b.WriteString(clrBorder("║") + " " + headLine + " " + clrBorder("║") + "\n")
	} else {
		b.WriteString("║ " + headLine + " ║\n")
	}
	b.WriteString(rowSepTw(tw, useColor))
	b.WriteByte('\n')

	for _, row := range rows {
		cells := make([]string, n)
		for i := 0; i < n; i++ {
			cell := ""
			if i < len(row) {
				cell = strings.TrimSpace(row[i])
			}
			cs := truncateRunes(cell, colW)
			pad := colW - len([]rune(cs))
			if pad < 0 {
				pad = 0
			}
			if useColor {
				cells[i] = clrDim(cs) + strings.Repeat(" ", pad)
			} else {
				cells[i] = cs + strings.Repeat(" ", pad)
			}
		}
		line := strings.Join(cells, sepCell)
		if useColor {
			b.WriteString(clrBorder("║") + " " + line + " " + clrBorder("║") + "\n")
		} else {
			b.WriteString("║ " + line + " ║\n")
		}
	}
	b.WriteString(boxBottomTw(tw, useColor))
	b.WriteByte('\n')
	return b.String()
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

func RenderReportText(r *SystemReport, useColor bool) string {
	tw := effectiveTermWidth()
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
	o.WriteString(tableKeyValueTw(tw, "Host & session", hostRows, useColor))
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
	o.WriteString(tableKeyValueTw(tw, "Network summary", netRows, useColor))
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
		o.WriteString(tableMultiHeaderTw(tw, "Interfaces", []string{"Name", "Type", "Addresses"}, rows, useColor))
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
		o.WriteString(tableMultiHeaderTw(tw, "Wi‑Fi networks (scan)", []string{"SSID", "Signal", "Security", "Active"}, rows, useColor))
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
	o.WriteString(tableKeyValueTw(tw, "Processor (CPU)", cpuRows, useColor))
	o.WriteString("\n")
	o.WriteString(barLineTw(tw, "CPU load", r.CPUUsagePct, useColor))
	o.WriteByte('\n')

	gpuList := r.GPUNames
	if len(gpuList) == 0 {
		gpuList = []string{"(no GPU detected via OS query)"}
	}
	var gpuRows [][2]string
	for i, g := range gpuList {
		gpuRows = append(gpuRows, [2]string{fmt.Sprintf("GPU #%d", i+1), g})
	}
	o.WriteString(tableKeyValueTw(tw, "Graphics (GPU)", gpuRows, useColor))
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
	o.WriteString(tableKeyValueTw(tw, "Memory (RAM)", memRows, useColor))
	o.WriteString("\n")
	o.WriteString(barLineTw(tw, "RAM usage", r.RAMUsedPct, useColor))
	o.WriteByte('\n')

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
	o.WriteString(tableKeyValueTw(tw, "Storage (all mounted volumes)", storRows, useColor))
	o.WriteString("\n")
	o.WriteString(barLineTw(tw, "Disk used (total)", pctUsed, useColor))
	o.WriteByte('\n')

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
		o.WriteString(tableMultiHeaderTw(tw, "Per-volume breakdown", []string{"Mount", "Medium", "Size", "Used", "Free", "Used%"}, rows, useColor))
		o.WriteString("\n")
		for _, d := range r.Disks {
			o.WriteString(barLineTw(tw, d.Mountpoint, d.UsedPct, useColor))
		}
		o.WriteString("\n")
	}

	if len(r.Thermal) > 0 {
		var trows [][2]string
		for _, t := range r.Thermal {
			trows = append(trows, [2]string{t.Label, fmt.Sprintf("%.1f °C", t.TempC)})
		}
		o.WriteString(tableKeyValueTw(tw, "Thermal sensors", trows, useColor))
		o.WriteString("\n")
	}

	if len(r.NetIO) > 0 {
		var rows [][]string
		for _, n := range r.NetIO {
			rows = append(rows, []string{n.Name, formatBytes(n.Rx), formatBytes(n.Tx), fmt.Sprintf("%d / %d", n.PRx, n.PTx)})
		}
		o.WriteString(tableMultiHeaderTw(tw, "Network I/O (since boot)", []string{"Iface", "RX", "TX", "Packets rx/tx"}, rows, useColor))
		o.WriteString("\n")
	}

	var runRows [][2]string
	runRows = append(runRows, [2]string{"PID", fmt.Sprintf("%d", r.PID)})
	runRows = append(runRows, [2]string{"Go runtime", r.GoVersion})
	runRows = append(runRows, [2]string{"Goroutines (this tool)", fmt.Sprintf("%d", r.Goroutines)})
	runRows = append(runRows, [2]string{"Processes visible", fmt.Sprintf("%d", r.ProcVis)})
	o.WriteString(tableKeyValueTw(tw, "Runtime (scanner)", runRows, useColor))

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
