package pcutilities

import (
	"fmt"
	"html"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func stripANSI(s string) string {
	var b strings.Builder
	in := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\x1b' {
			in = true
			continue
		}
		if in {
			if c == 'm' {
				in = false
			}
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func ExportReportFiles(r *SystemReport) (txtPath, htmlPath string, err error) {
	dir := pathPCReportsDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", "", err
	}
	base := fmt.Sprintf("system_report_%s", r.CollectedAt.Format("20060102_150405"))
	txtPath = filepath.Join(dir, base+".txt")
	htmlPath = filepath.Join(dir, base+".html")

	plain := RenderReportTextWidth(r, false, effectiveTermWidth())
	if err := os.WriteFile(txtPath, []byte(plain), 0644); err != nil {
		return "", "", err
	}
	htmlContent := buildHTMLReport(r)
	if err := os.WriteFile(htmlPath, []byte(htmlContent), 0644); err != nil {
		return txtPath, "", err
	}
	return txtPath, htmlPath, nil
}

func buildHTMLReport(r *SystemReport) string {
	pctUsed := 0.0
	if r.DiskTotalBytes > 0 {
		pctUsed = float64(r.DiskUsedBytes) * 100 / float64(r.DiskTotalBytes)
	}
	var disksHTML strings.Builder
	for i, d := range r.Disks {
		disksHTML.WriteString(diskCardHTML(d, i))
	}
	wifiRows := ""
	for _, w := range r.WiFiNetworks {
		act := "no"
		if w.Active {
			act = "yes"
		}
		bssid := strings.TrimSpace(w.BSSID)
		if bssid == "" {
			bssid = "—"
		}
		wifiRows += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			html.EscapeString(w.SSID), html.EscapeString(bssid), html.EscapeString(w.Signal), html.EscapeString(w.Security), act)
	}
	if wifiRows == "" {
		wifiRows = "<tr><td colspan=\"5\">—</td></tr>"
	}
	gpu := strings.Join(r.GPUNames, "; ")
	if gpu == "" {
		gpu = "(none detected)"
	}
	ifaceRows := ""
	for _, iface := range r.InterfaceRows {
		typ := "Ethernet"
		if iface.IsWifi {
			typ = "Wi‑Fi"
		}
		mac := strings.TrimSpace(iface.Hardware)
		if mac == "" {
			mac = "—"
		}
		ifaceRows += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			html.EscapeString(iface.Name), typ, html.EscapeString(mac), html.EscapeString(strings.Join(iface.Addrs, ", ")))
	}
	if ifaceRows == "" {
		ifaceRows = "<tr><td colspan=\"4\">—</td></tr>"
	}
	defMAC := ""
	for _, iface := range r.InterfaceRows {
		if iface.Name == r.DefaultIface && strings.TrimSpace(iface.Hardware) != "" {
			defMAC = iface.Hardware
			break
		}
	}
	if defMAC == "" {
		defMAC = "—"
	}
	pub := html.EscapeString(r.PublicIP)
	if r.PublicIP == "" {
		pub = "— (" + html.EscapeString(r.PublicIPErr) + ")"
	}

	chartsHTML := htmlChartsRow(r)
	extrasHTML := htmlExtrasSections(r)

	diskAggNote := ""
	if r.DiskTotalBytes > 0 {
		pctFree := float64(r.DiskFreeBytes) * 100 / float64(r.DiskTotalBytes)
		if math.Abs(100-pctUsed-pctFree) > 0.75 {
			diskAggNote = fmt.Sprintf(`<p class="muted" style="margin-top:10px;font-size:.82rem;">Summed volumes: about %.1f%% used and %.1f%% free of summed capacity; totals can differ from 100%% when mount points overlap the same storage.</p>`,
				pctUsed, pctFree)
		}
	}

	inner := fmt.Sprintf(`
<body>
<div class="bg-aurora" aria-hidden="true"></div>
<div class="wrap">
<header class="hero">
<h1 class="glitch" data-text="ECLIPSE">ECLIPSE</h1>
<p class="tag">System report · live metrics</p>
<p class="meta">%s · <strong>%s</strong></p>
</header>

%s

<div class="grid">
<section class="card card-a stack" style="--d:0.05s">
<h2>Network</h2>
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Local IPs</td><td>%s</td></tr>
<tr><td>Public IP</td><td>%s</td></tr>
<tr><td>Active</td><td>%s</td></tr>
<tr><td>MAC (default iface)</td><td>%s</td></tr>
<tr><td>Link speed (~1s sample)</td><td>↓ %.2f Mbps · ↑ %.2f Mbps</td></tr>
<tr><td>Wi‑Fi BSSID (current)</td><td>%s</td></tr>
<tr><td>Wi‑Fi passphrase</td><td>Never exported (security policy)</td></tr>
<tr><td>Notes</td><td>%s</td></tr>
</table>
</section>

<section class="card card-b stack" style="--d:0.12s">
<h2>CPU &amp; GPU</h2>
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>CPU</td><td>%s</td></tr>
<tr><td>Usage</td><td><span class="pill">%.1f%%</span></td></tr>
<tr><td>Cores</td><td>%d phys / %d logical</td></tr>
<tr><td>GPU</td><td>%s</td></tr>
</table>
<div class="barwrap" title="CPU"><div class="barfill bar-cpu" style="width:%.3f%%"></div></div>
</section>

<section class="card card-c stack" style="--d:0.19s">
<h2>Memory</h2>
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>RAM</td><td>%s used of %s <span class="pill">%.1f%%</span></td></tr>
<tr><td>Swap</td><td>%s / %s</td></tr>
</table>
<div class="barwrap"><div class="barfill bar-ram" style="width:%.3f%%"></div></div>
</section>

<section class="card card-d stack" style="--d:0.26s">
<h2>Storage total</h2>
<p class="big">%s <span class="muted">used of</span> %s</p>
<p class="pct-label"><strong>%.1f%%</strong> used</p>
<div class="barwrap bar-fat"><div class="barfill bar-disk" style="width:%.3f%%"></div></div>
%s
</section>
</div>

<section class="card wide stack" style="--d:0.32s">
<h2>Interfaces</h2>
<table>
<tr><th>Name</th><th>Type</th><th>MAC</th><th>Addresses</th></tr>
%s
</table>
</section>

<section class="card wide stack" style="--d:0.38s">
<h2>Wi‑Fi</h2>
<table>
<tr><th>SSID</th><th>BSSID</th><th>Signal</th><th>Security</th><th>Active</th></tr>
%s
</table>
</section>

<section class="card wide disks-section stack" style="--d:0.44s">
<h2>Volumes · animated bars</h2>
<div class="diskgrid">
%s
</div>
</section>

%s
</div>
</body>`,
		html.EscapeString(r.CollectedAt.Format(time.RFC3339)),
		html.EscapeString(r.Hostname),
		chartsHTML,
		html.EscapeString(strings.Join(dedupeKeepOrder(r.LocalIPs), ", ")),
		pub,
		html.EscapeString(nz(r.ActiveConn)),
		html.EscapeString(defMAC),
		r.NetDownMbps,
		r.NetUpMbps,
		html.EscapeString(nz(r.WiFiBSSIDCurrent)),
		html.EscapeString(r.WiFiSecurityNote),
		html.EscapeString(r.CPUModel),
		r.CPUUsagePct,
		r.CPUPhysical,
		r.CPULogical,
		html.EscapeString(gpu),
		r.CPUUsagePct,
		formatBytes(r.RAMUsed),
		formatBytes(r.RAMTotal),
		r.RAMUsedPct,
		formatBytes(r.SwapUsed),
		formatBytes(r.SwapTotal),
		r.RAMUsedPct,
		formatBytes(r.DiskUsedBytes),
		formatBytes(r.DiskTotalBytes),
		pctUsed,
		pctUsed,
		diskAggNote,
		ifaceRows,
		wifiRows,
		disksHTML.String(),
		extrasHTML,
	)

	head := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ECLIPSE · ` + html.EscapeString(r.Hostname) + `</title>
` + htmlReportStyles() + `
</head>
`
	return head + inner + "\n</html>"
}

func diskCardHTML(d DiskVol, idx int) string {
	return fmt.Sprintf(`<div class="diskcard" style="--i:%d">
<h3>%s · %s</h3>
<p class="meta2">%s · %s total · %s free</p>
<div class="barwrap"><div class="barfill bar-disk" style="width:%.3f%%"></div></div>
<p class="pct-label" style="margin:10px 0 0;font-size:.82rem;">%.1f%% used</p>
</div>`,
		idx,
		html.EscapeString(d.Mountpoint),
		html.EscapeString(d.Medium),
		html.EscapeString(d.Fstype),
		formatBytes(d.Total),
		formatBytes(d.Free),
		d.UsedPct,
		d.UsedPct,
	)
}
