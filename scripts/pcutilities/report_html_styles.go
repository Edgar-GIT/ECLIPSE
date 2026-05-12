package pcutilities

func htmlReportStyles() string {
	return `<style>
:root{
  --neon1:#ff006e;--neon2:#00f5d4;--neon3:#fee440;--neon4:#9b5de5;
  --bg0:#070a12;--glass:rgba(25,32,72,.58);
}
*{box-sizing:border-box}
html,body{min-height:100%;margin:0}
body{
  font-family:ui-sans-serif,system-ui,"Segoe UI",Roboto,sans-serif;
  color:#e8f0ff;background:var(--bg0);overflow-x:hidden;line-height:1.45;
}
.bg-aurora{
  position:fixed;inset:-40%;z-index:0;pointer-events:none;opacity:.5;
  background:
    radial-gradient(ellipse 80% 50% at 20% 20%,rgba(255,0,110,.22),transparent 50%),
    radial-gradient(ellipse 60% 40% at 80% 30%,rgba(0,245,212,.18),transparent 45%),
    radial-gradient(ellipse 50% 60% at 50% 90%,rgba(155,93,229,.2),transparent 40%);
  animation:aurora 18s ease-in-out infinite alternate;
}
@keyframes aurora{
  0%{transform:translate(0,0) rotate(0deg)}
  100%{transform:translate(-4%,3%) rotate(8deg)}
}
@media (prefers-reduced-motion:reduce){
  .bg-aurora,.card,.barfill,.glitch::after,.pie,.hbar-fill{animation:none!important}
  .barfill,.hbar-fill{width:var(--w)!important}
  .pie{transform:none!important;opacity:1!important}
  .card{opacity:1;transform:none}
}
.wrap{position:relative;z-index:1;max-width:1180px;margin:0 auto;padding:28px 22px 56px}
.hero{margin-bottom:28px}
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
  0%,100%{transform:translate(0);clip-path:inset(0 0 95% 0)}
  20%{transform:translate(-2px,1px);clip-path:inset(30% 0 40% 0)}
  40%{transform:translate(2px,-1px);clip-path:inset(10% 0 70% 0)}
}
.tag{margin:6px 0 0;font-size:.78rem;text-transform:uppercase;letter-spacing:.28em;color:#7a8ab8}
.meta{margin:10px 0 0;font-size:.88rem;color:#9aaee5}
.grid{display:grid;gap:22px;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));margin-bottom:28px}
.card{
  background:var(--glass);border:1px solid rgba(155,93,229,.35);border-radius:18px;
  padding:20px 22px 22px;backdrop-filter:blur(12px);margin-bottom:26px;
  box-shadow:0 12px 40px rgba(0,0,0,.42),0 0 0 1px rgba(0,245,212,.08) inset;
  animation:rise .75s cubic-bezier(.22,1,.36,1) backwards;
  animation-delay:var(--d,.1s);
  transition:transform .25s ease,box-shadow .25s ease,border-color .25s;
}
.card:hover{
  transform:translateY(-3px);
  box-shadow:0 20px 50px rgba(255,0,110,.14),0 0 32px rgba(0,245,212,.12);
  border-color:rgba(0,245,212,.45);
}
.card h2{
  margin:0 0 14px;font-size:.95rem;font-weight:700;
  color:#b8cfff;text-transform:uppercase;letter-spacing:.12em;
  border-bottom:1px solid rgba(255,0,110,.28);padding-bottom:8px;
}
.card-a{border-top:3px solid var(--neon1)}
.card-b{border-top:3px solid var(--neon2)}
.card-c{border-top:3px solid var(--neon3)}
.card-d{border-top:3px solid var(--neon4)}
.wide{grid-column:1/-1}
table{width:100%;border-collapse:collapse;font-size:.87rem}
th{text-align:left;color:#8ebfff;padding:10px 8px;border-bottom:1px solid rgba(0,245,212,.28)}
td{padding:10px 8px;border-bottom:1px solid rgba(80,90,130,.22);color:#dde6ff;vertical-align:top}
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
  margin-top:14px;height:14px;background:rgba(0,0,0,.45);border-radius:999px;
  overflow:hidden;border:1px solid rgba(255,0,110,.28);
}
.bar-fat{height:20px}
.barfill{
  height:100%;width:0;border-radius:999px;
  background:linear-gradient(90deg,var(--neon2),var(--neon3),var(--neon1));
  background-size:200% 100%;
  box-shadow:0 0 20px rgba(0,245,212,.45);
  animation:fillw 1.35s cubic-bezier(.22,1,.36,1) forwards,shimmer 2.8s linear infinite,glowpulse 2.2s ease-in-out infinite;
  animation-delay:.12s,.18s,0s;
}
.bar-cpu{background:linear-gradient(90deg,#00f5d4,#9b5de5,#ff006e);background-size:200% 100%}
.bar-ram{background:linear-gradient(90deg,#fee440,#00bbf9,#9b5de5);background-size:200% 100%}
.bar-disk{background:linear-gradient(90deg,#ff006e,#fee440,#00f5d4);background-size:200% 100%}
@keyframes fillw{to{width:var(--w)}}
@keyframes shimmer{
  0%{background-position:0% 50%}
  100%{background-position:200% 50%}
}
@keyframes glowpulse{
  0%,100%{filter:brightness(1)}
  50%{filter:brightness(1.15)}
}
@keyframes rise{
  from{opacity:0;transform:translateY(16px) scale(.98)}
  to{opacity:1;transform:none}
}
.charts-row{
  display:flex;flex-wrap:wrap;gap:28px;align-items:flex-end;justify-content:space-between;
  margin:6px 0 8px;padding:8px 0 4px;
}
.donut-wrap{text-align:center;min-width:140px}
.donut-wrap figcaption{margin-top:8px;font-size:.78rem;color:#9aaee5;max-width:160px;margin-left:auto;margin-right:auto}
.donut-wrap strong{color:#e8f0ff;font-size:1rem}
.pie{
  width:118px;height:118px;margin:0 auto;border-radius:50%;
  background:conic-gradient(var(--c1) calc(var(--p)*1%),#242a42 0);
  -webkit-mask:radial-gradient(farthest-side,#0000 58%,#000 59%);
  mask:radial-gradient(farthest-side,#0000 58%,#000 59%);
  box-shadow:0 0 22px rgba(0,245,212,.12);
  animation:piezoom .85s cubic-bezier(.22,1,.36,1) backwards;
}
@keyframes piezoom{
  from{transform:scale(.55) rotate(-20deg);opacity:0}
  to{transform:scale(1) rotate(0);opacity:1}
}
.hbar-block{flex:1;min-width:180px;max-width:320px;margin-bottom:8px}
.hbar-label{font-size:.72rem;color:#8ebfff;margin-bottom:6px;text-transform:uppercase;letter-spacing:.1em}
.hbar-track{height:12px;border-radius:999px;background:rgba(0,0,0,.45);border:1px solid rgba(0,245,212,.2);overflow:hidden}
.hbar-fill.bar-cpu{background:linear-gradient(90deg,#00f5d4,#9b5de5,#ff006e);background-size:200% 100%;animation:hfill 1.2s cubic-bezier(.22,1,.36,1) forwards,shimmer 2.8s linear infinite}
.hbar-fill.bar-ram{background:linear-gradient(90deg,#fee440,#00bbf9,#9b5de5);background-size:200% 100%;animation:hfill 1.2s cubic-bezier(.22,1,.36,1) forwards,shimmer 2.8s linear infinite}
.hbar-fill.bar-disk{background:linear-gradient(90deg,#ff006e,#fee440,#00f5d4);background-size:200% 100%;animation:hfill 1.2s cubic-bezier(.22,1,.36,1) forwards,shimmer 2.8s linear infinite}
@keyframes hfill{to{width:var(--w)}}
.diskgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:20px;margin-top:8px}
.diskcard{
  background:rgba(12,16,36,.78);border-radius:16px;padding:18px;margin-bottom:4px;
  border:1px solid rgba(0,245,212,.22);
  animation:rise .7s cubic-bezier(.22,1,.36,1) backwards;
  animation-delay:calc(.15s + var(--i) * .07s);
  transition:transform .2s,border-color .2s;
}
.diskcard:hover{transform:scale(1.02);border-color:rgba(255,0,110,.5)}
.diskcard h3{margin:0 0 8px;font-size:.9rem;color:#9ed8ff}
.diskcard .meta2{font-size:.8rem;color:#7a87b0;margin:0 0 10px}
.diskcard .barwrap{margin-top:8px}
.mono-list{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.78rem;color:#c9d6ff;white-space:pre-wrap;background:rgba(0,0,0,.35);padding:12px 14px;border-radius:12px;border:1px solid rgba(155,93,229,.25);max-height:320px;overflow:auto}
.stack{margin-bottom:32px}
</style>`
}
