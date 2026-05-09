package pcutilities

import (
	"fmt"
	"html"
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

	plain := RenderReportText(r, false)
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
	for _, d := range r.Disks {
		disksHTML.WriteString(diskCardHTML(d))
	}
	wifiRows := ""
	for _, w := range r.WiFiNetworks {
		act := "no"
		if w.Active {
			act = "yes"
		}
		wifiRows += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			html.EscapeString(w.SSID), html.EscapeString(w.Signal), html.EscapeString(w.Security), act)
	}
	if wifiRows == "" {
		wifiRows = "<tr><td colspan=\"4\">—</td></tr>"
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
		ifaceRows += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			html.EscapeString(iface.Name), typ, html.EscapeString(strings.Join(iface.Addrs, ", ")))
	}
	if ifaceRows == "" {
		ifaceRows = "<tr><td colspan=\"3\">—</td></tr>"
	}
	pub := html.EscapeString(r.PublicIP)
	if r.PublicIP == "" {
		pub = "— (" + html.EscapeString(r.PublicIPErr) + ")"
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>System report %s</title>
<style>
body{font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,sans-serif;background:linear-gradient(160deg,#0a0e1a 0%%,#12182a 40%%,#0d1220 100%%);color:#e8ecff;margin:0;padding:32px;}
h1{font-size:1.35rem;font-weight:600;background:linear-gradient(90deg,#7ecbff,#c79bff,#ff9b9b);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin:0 0 8px;}
.sub{color:#8892b0;font-size:0.85rem;margin-bottom:28px;}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin-bottom:24px;}
.card{background:rgba(30,38,68,.55);border:1px solid rgba(120,140,255,.25);border-radius:14px;padding:16px 18px;box-shadow:0 8px 32px rgba(0,0,0,.35);}
.card h2{margin:0 0 12px;font-size:0.95rem;color:#a8b8ff;letter-spacing:0.02em;}
table{width:100%%;border-collapse:collapse;font-size:0.88rem;}
th{text-align:left;color:#9aa7d4;padding:8px 6px;border-bottom:1px solid rgba(120,140,255,.2);}
td{padding:8px 6px;border-bottom:1px solid rgba(80,90,120,.15);color:#d4daf0;}
.barwrap{margin-top:10px;height:22px;background:rgba(0,0,0,.35);border-radius:8px;overflow:hidden;border:1px solid rgba(120,140,255,.2);}
.barfill{height:100%%;border-radius:6px;background:linear-gradient(90deg,#3dff9e,#ffe66d,#ff6b6b);box-shadow:0 0 16px rgba(120,200,255,.35);}
.diskgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px;}
.diskcard{background:rgba(22,28,48,.7);border-radius:12px;padding:14px;border:1px solid rgba(100,120,200,.2);}
.diskcard h3{margin:0 0 8px;font-size:0.88rem;color:#b8c8ff;}
</style>
</head>
<body>
<h1>ECLIPSE system report</h1>
<div class="sub">Generated %s · Host %s</div>
<div class="grid">
<div class="card"><h2>Network</h2>
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Local IPs</td><td>%s</td></tr>
<tr><td>Public IP</td><td>%s</td></tr>
<tr><td>Active</td><td>%s</td></tr>
</table></div>
<div class="card"><h2>CPU &amp; GPU</h2>
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>CPU</td><td>%s</td></tr>
<tr><td>Usage</td><td>%.1f%%</td></tr>
<tr><td>Cores</td><td>%d phys / %d logical</td></tr>
<tr><td>GPU</td><td>%s</td></tr>
</table></div>
<div class="card"><h2>Memory</h2>
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>RAM</td><td>%s used of %s (%.1f%%)</td></tr>
<tr><td>Swap</td><td>%s / %s</td></tr>
</table>
<div class="barwrap"><div class="barfill" style="width:%.1f%%"></div></div>
</div>
<div class="card"><h2>Storage total</h2>
<p>%s used of %s · <strong>%.1f%%</strong> used</p>
<div class="barwrap"><div class="barfill" style="width:%.1f%%"></div></div>
</div>
</div>
<div class="card" style="margin-bottom:20px;"><h2>Interfaces</h2>
<table>
<tr><th>Name</th><th>Type</th><th>Addresses</th></tr>
%s
</table></div>
<div class="card" style="margin-bottom:20px;"><h2>Wi‑Fi</h2>
<table>
<tr><th>SSID</th><th>Signal</th><th>Security</th><th>Active</th></tr>
%s
</table></div>
<div class="card"><h2>Volumes &amp; disk bars</h2>
<div class="diskgrid">
%s
</div>
</div>
</body>
</html>`,
		html.EscapeString(r.CollectedAt.Format(time.RFC3339)),
		html.EscapeString(r.CollectedAt.Format(time.RFC3339)),
		html.EscapeString(r.Hostname),
		html.EscapeString(strings.Join(dedupeKeepOrder(r.LocalIPs), ", ")),
		html.EscapeString(pub),
		html.EscapeString(nz(r.ActiveConn)),
		html.EscapeString(r.CPUModel),
		r.CPUUsagePct,
		r.CPUPhysical,
		r.CPULogical,
		html.EscapeString(gpu),
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
		ifaceRows,
		wifiRows,
		disksHTML.String(),
	)
}

func diskCardHTML(d DiskVol) string {
	return fmt.Sprintf(`<div class="diskcard"><h3>%s · %s</h3>
<p style="margin:0 0 8px;font-size:0.82rem;color:#8892b0;">%s · %s total · %s free</p>
<div class="barwrap"><div class="barfill" style="width:%.1f%%"></div></div>
<p style="margin:8px 0 0;font-size:0.8rem;">%.1f%% used</p></div>`,
		html.EscapeString(d.Mountpoint),
		html.EscapeString(d.Medium),
		html.EscapeString(d.Fstype),
		formatBytes(d.Total),
		formatBytes(d.Free),
		d.UsedPct,
		d.UsedPct,
	)
}
