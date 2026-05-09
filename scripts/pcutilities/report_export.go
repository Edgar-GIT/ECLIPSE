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
	for i, d := range r.Disks {
		disksHTML.WriteString(diskCardHTML(d, i))
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

	inner := fmt.Sprintf(`
<body>
<div class="bg-aurora" aria-hidden="true"></div>
<div class="wrap">
<header class="hero">
<h1 class="glitch" data-text="ECLIPSE">ECLIPSE</h1>
<p class="tag">System report · live metrics</p>
<p class="meta">%s · <strong>%s</strong></p>
</header>

<div class="grid">
<section class="card card-a" style="--d:0.05s">
<h2>Network</h2>
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Local IPs</td><td>%s</td></tr>
<tr><td>Public IP</td><td>%s</td></tr>
<tr><td>Active</td><td>%s</td></tr>
</table>
</section>

<section class="card card-b" style="--d:0.12s">
<h2>CPU &amp; GPU</h2>
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>CPU</td><td>%s</td></tr>
<tr><td>Usage</td><td><span class="pill">%.1f%%</span></td></tr>
<tr><td>Cores</td><td>%d phys / %d logical</td></tr>
<tr><td>GPU</td><td>%s</td></tr>
</table>
<div class="barwrap" title="CPU"><div class="barfill bar-cpu" style="--w:%.3f%%"></div></div>
</section>

<section class="card card-c" style="--d:0.19s">
<h2>Memory</h2>
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>RAM</td><td>%s used of %s <span class="pill">%.1f%%</span></td></tr>
<tr><td>Swap</td><td>%s / %s</td></tr>
</table>
<div class="barwrap"><div class="barfill bar-ram" style="--w:%.3f%%"></div></div>
</section>

<section class="card card-d" style="--d:0.26s">
<h2>Storage total</h2>
<p class="big">%s <span class="muted">used of</span> %s</p>
<p class="pct-label"><strong>%.1f%%</strong> used</p>
<div class="barwrap bar-fat"><div class="barfill bar-disk" style="--w:%.3f%%"></div></div>
</section>
</div>

<section class="card wide" style="--d:0.32s">
<h2>Interfaces</h2>
<table>
<tr><th>Name</th><th>Type</th><th>Addresses</th></tr>
%s
</table>
</section>

<section class="card wide" style="--d:0.38s">
<h2>Wi‑Fi</h2>
<table>
<tr><th>SSID</th><th>Signal</th><th>Security</th><th>Active</th></tr>
%s
</table>
</section>

<section class="card wide disks-section" style="--d:0.44s">
<h2>Volumes · animated bars</h2>
<div class="diskgrid">
%s
</div>
</section>
</div>
</body>`,
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
		ifaceRows,
		wifiRows,
		disksHTML.String(),
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

func htmlReportStyles() string {
	return `<style>
:root{
  --neon1:#ff006e;--neon2:#00f5d4;--neon3:#fee440;--neon4:#9b5de5;
  --bg0:#070a12;--bg1:#0f1430;--glass:rgba(25,32,72,.55);
}
*{box-sizing:border-box}
html,body{min-height:100%;margin:0}
body{
  font-family:ui-sans-serif,system-ui,"Segoe UI",Roboto,sans-serif;
  color:#e8f0ff;background:var(--bg0);overflow-x:hidden;
}
.bg-aurora{
  position:fixed;inset:-40%;z-index:0;pointer-events:none;opacity:.55;
  background:
    radial-gradient(ellipse 80%% 50%% at 20%% 20%%,rgba(255,0,110,.25),transparent 50%%),
    radial-gradient(ellipse 60%% 40%% at 80%% 30%%,rgba(0,245,212,.2),transparent 45%%),
    radial-gradient(ellipse 50%% 60%% at 50%% 90%%,rgba(155,93,229,.22),transparent 40%%);
  animation:aurora 18s ease-in-out infinite alternate;
}
@keyframes aurora{
  0%%{transform:translate(0,0) rotate(0deg)}
  100%%{transform:translate(-4%%,3%%) rotate(8deg)}
}
@media (prefers-reduced-motion:reduce){
  .bg-aurora,.card,.barfill,.glitch::after{animation:none!important}
  .barfill{width:var(--w)!important}
  .card{opacity:1;transform:none}
}
.wrap{position:relative;z-index:1;max-width:1180px;margin:0 auto;padding:28px 22px 48px}
.hero{margin-bottom:26px}
.hero h1{
  font-size:clamp(1.8rem,4vw,2.6rem);font-weight:800;letter-spacing:.06em;margin:0;
  background:linear-gradient(105deg,var(--neon1),var(--neon3),var(--neon2));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
}
.glitch{position:relative}
.glitch::after{
  content:attr(data-text);position:absolute;left:2px;top:0;
  background:linear-gradient(90deg,var(--neon4),var(--neon1));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  clip-path:inset(0 0 0 0);animation:glitch 3.2s steps(2,end) infinite;
  opacity:.35;pointer-events:none;
}
@keyframes glitch{
  0%%,100%%{transform:translate(0);clip-path:inset(0 0 95%% 0)}
  20%%{transform:translate(-2px,1px);clip-path:inset(30%% 0 40%% 0)}
  40%%{transform:translate(2px,-1px);clip-path:inset(10%% 0 70%% 0)}
}
.tag{margin:6px 0 0;font-size:.78rem;text-transform:uppercase;letter-spacing:.28em;color:#7a8ab8}
.meta{margin:10px 0 0;font-size:.88rem;color:#9aaee5}
.grid{display:grid;gap:18px;grid-template-columns:repeat(auto-fit,minmax(260px,1fr))}
.card{
  background:var(--glass);border:1px solid rgba(155,93,229,.35);border-radius:18px;
  padding:18px 20px;backdrop-filter:blur(12px);
  box-shadow:0 12px 40px rgba(0,0,0,.4),0 0 0 1px rgba(0,245,212,.08) inset;
  animation:rise .75s cubic-bezier(.22,1,.36,1) backwards;
  animation-delay:var(--d,.1s);
  transition:transform .25s ease,box-shadow .25s ease,border-color .25s;
}
.card:hover{
  transform:translateY(-4px);
  box-shadow:0 20px 50px rgba(255,0,110,.15),0 0 32px rgba(0,245,212,.12);
  border-color:rgba(0,245,212,.45);
}
.card h2{
  margin:0 0 14px;font-size:.95rem;font-weight:700;
  color:#b8cfff;text-transform:uppercase;letter-spacing:.12em;
  border-bottom:1px solid rgba(255,0,110,.25);padding-bottom:8px;
}
.card-a{border-top:3px solid var(--neon1)}
.card-b{border-top:3px solid var(--neon2)}
.card-c{border-top:3px solid var(--neon3)}
.card-d{border-top:3px solid var(--neon4)}
.wide{grid-column:1/-1}
table{width:100%%;border-collapse:collapse;font-size:.87rem}
th{text-align:left;color:#8ebfff;padding:10px 8px;border-bottom:1px solid rgba(0,245,212,.25)}
td{padding:10px 8px;border-bottom:1px solid rgba(80,90,130,.2);color:#dde6ff}
tr:hover td{background:rgba(0,245,212,.06)}
.pill{
  display:inline-block;padding:2px 10px;border-radius:999px;
  background:linear-gradient(90deg,rgba(255,0,110,.25),rgba(0,245,212,.2));
  border:1px solid rgba(255,255,255,.12);font-weight:600;
}
.big{font-size:1.05rem;margin:0 0 6px}
.muted{color:#8892b8;font-weight:400}
.pct-label{margin:0 0 12px;color:var(--neon3)}
.barwrap{
  margin-top:12px;height:14px;background:rgba(0,0,0,.45);border-radius:999px;
  overflow:hidden;border:1px solid rgba(255,0,110,.25);
}
.bar-fat{height:20px}
.barfill{
  height:100%%;width:0;border-radius:999px;
  background:linear-gradient(90deg,var(--neon2),var(--neon3),var(--neon1));
  background-size:200%% 100%%;
  box-shadow:0 0 20px rgba(0,245,212,.45);
  animation:fillw 1.35s cubic-bezier(.22,1,.36,1) forwards,shimmer 2.8s linear infinite;
  animation-delay:.15s,.2s;
}
.bar-cpu{background:linear-gradient(90deg,#00f5d4,#9b5de5,#ff006e);background-size:200%% 100%%}
.bar-ram{background:linear-gradient(90deg,#fee440,#00bbf9,#9b5de5);background-size:200%% 100%%}
.bar-disk{background:linear-gradient(90deg,#ff006e,#fee440,#00f5d4);background-size:200%% 100%%}
@keyframes fillw{to{width:var(--w)}}
@keyframes shimmer{
  0%%{background-position:0%% 50%%}
  100%%{background-position:200%% 50%%}
}
@keyframes rise{
  from{opacity:0;transform:translateY(16px) scale(.98)}
  to{opacity:1;transform:none}
}
.diskgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:16px}
.diskcard{
  background:rgba(12,16,36,.75);border-radius:16px;padding:16px;
  border:1px solid rgba(0,245,212,.2);
  animation:rise .7s cubic-bezier(.22,1,.36,1) backwards;
  animation-delay:calc(.15s + var(--i) * .07s);
  transition:transform .2s,border-color .2s;
}
.diskcard:hover{transform:scale(1.02);border-color:rgba(255,0,110,.5)}
.diskcard h3{margin:0 0 8px;font-size:.9rem;color:#9ed8ff}
.diskcard .meta2{font-size:.8rem;color:#7a87b0;margin:0 0 10px}
.diskcard .barwrap{margin-top:8px}
</style>`
}

func diskCardHTML(d DiskVol, idx int) string {
	return fmt.Sprintf(`<div class="diskcard" style="--i:%d">
<h3>%s · %s</h3>
<p class="meta2">%s · %s total · %s free</p>
<div class="barwrap"><div class="barfill bar-disk" style="--w:%.3f%%"></div></div>
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
