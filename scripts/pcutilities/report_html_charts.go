package pcutilities

import (
	"fmt"
	"html"
	"strings"
)

func htmlDonutFigure(pct float64, caption, colorVar string) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return fmt.Sprintf(
		`<figure class="donut-wrap"><div class="pie" style="--p:%.3f;--c1:%s" role="img" aria-label="%s %.0f%%"></div><figcaption>%s<br><strong>%.0f%%</strong></figcaption></figure>`,
		pct, colorVar, html.EscapeString(caption), pct, html.EscapeString(caption), pct,
	)
}

func htmlChartsRow(r *SystemReport) string {
	pDisk := 0.0
	if r.DiskTotalBytes > 0 {
		pDisk = float64(r.DiskUsedBytes) * 100 / float64(r.DiskTotalBytes)
	}
	var b strings.Builder
	b.WriteString(`<div class="charts-row">`)
	b.WriteString(htmlDonutFigure(r.CPUUsagePct, "CPU load", "#00f5d4"))
	b.WriteString(htmlDonutFigure(r.RAMUsedPct, "RAM used", "#fee440"))
	b.WriteString(htmlDonutFigure(pDisk, "Disk (aggregate)", "#ff006e"))
	b.WriteString(`</div><div class="charts-row">`)
	b.WriteString(htmlHBar("CPU (horizontal)", r.CPUUsagePct, "bar-cpu"))
	b.WriteString(htmlHBar("RAM (horizontal)", r.RAMUsedPct, "bar-ram"))
	b.WriteString(htmlHBar("Disk (horizontal)", pDisk, "bar-disk"))
	b.WriteString(`</div>`)
	return b.String()
}

func htmlHBar(title string, pct float64, cls string) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return fmt.Sprintf(
		`<div class="hbar-block"><div class="hbar-label">%s</div><div class="hbar-track"><div class="hbar-fill %s" style="--w:%.3f%%"></div></div></div>`,
		html.EscapeString(title), cls, pct,
	)
}

func htmlMonoBlock(title string, lines []string, max int) string {
	if len(lines) == 0 {
		return ""
	}
	if len(lines) > max {
		lines = lines[:max]
	}
	esc := html.EscapeString(strings.Join(lines, "\n"))
	return fmt.Sprintf(`<section class="card wide stack"><h2>%s</h2><pre class="mono-list">%s</pre></section>`,
		html.EscapeString(title), esc)
}

func htmlExtrasSections(r *SystemReport) string {
	var b strings.Builder
	if s := htmlMonoBlock("Listening sockets (sample)", r.ListenPorts, 60); s != "" {
		b.WriteString(s)
	}
	if s := htmlMonoBlock("Database-like processes", r.DBLikeProcesses, 30); s != "" {
		b.WriteString(s)
	}
	if s := htmlMonoBlock("Bluetooth devices", r.BluetoothDevices, 40); s != "" {
		b.WriteString(s)
	}
	if s := htmlMonoBlock("Audio (sinks / devices)", r.AudioDevices, 25); s != "" {
		b.WriteString(s)
	}
	if s := htmlMonoBlock("Displays (xrandr)", r.Monitors, 20); s != "" {
		b.WriteString(s)
	}
	if len(r.LoadedModules) > 0 {
		mod := strings.Join(r.LoadedModules, ", ")
		if len(mod) > 4000 {
			mod = mod[:3997] + "..."
		}
		b.WriteString(fmt.Sprintf(`<section class="card wide stack"><h2>Kernel modules (sample)</h2><p class="muted">%s</p></section>`,
			html.EscapeString(mod)))
	}
	if s := htmlMonoBlock("Home usage (du, top-level)", r.HomeTopDirs, 22); s != "" {
		b.WriteString(s)
	}
	if strings.TrimSpace(r.HomeLargestLine) != "" {
		b.WriteString(fmt.Sprintf(`<section class="card wide stack"><h2>Home — largest du line</h2><pre class="mono-list">%s</pre></section>`,
			html.EscapeString(r.HomeLargestLine)))
	}
	return b.String()
}
