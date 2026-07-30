package whatsapp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/chromedp/chromedp"
)

func ensureXDisplay() {
	if d := os.Getenv("DISPLAY"); d != "" {
		exec.Command("xauth", "generate", d, ".", "trusted").Run()
	}
}

func DiscoverReferenceProfile(outDir string) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	userDir, err := os.MkdirTemp("", "whatsapp-ref-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(userDir)

	ensureXDisplay()

	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoSandbox,
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("ozone-platform", "wayland"),
		chromedp.Env("DISPLAY="),
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.UserDataDir(userDir),
		chromedp.WindowSize(1280, 900),
	}
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

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
	var r string
	if err := chromedp.Run(ctx, chromedp.Evaluate(jsDump, &r)); err != nil {
		fmt.Printf("  dump failed: %v\n", err); return
	}
	var v interface{}
	json.Unmarshal([]byte(r), &v)
	data, _ := json.MarshalIndent(v, "", "  ")
	os.WriteFile(path, data, 0644)
	fmt.Printf("  Saved: %s (%d bytes)\n", filepath.Base(path), len(data))
}

func ReplayInBrowser(sd *sessionData) error {
	userDir, err := os.MkdirTemp("", "whatsapp-replay-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(userDir)

	ensureXDisplay()

	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoSandbox,
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("ozone-platform", "wayland"),
		chromedp.Env("DISPLAY="),
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.UserDataDir(userDir),
		chromedp.WindowSize(1280, 900),
	}
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	if err := chromedp.Run(ctx, chromedp.Navigate("https://web.whatsapp.com")); err != nil {
		return err
	}
	// Wait for the page to render QR (means IndexedDB is initialized with keys)
	if err := chromedp.Run(ctx, chromedp.WaitVisible("canvas", chromedp.ByQuery)); err != nil {
		return fmt.Errorf("wait QR: %w", err)
	}
	time.Sleep(2 * time.Second)

	var dump string
	if err := chromedp.Run(ctx, chromedp.Evaluate(jsDump, &dump)); err != nil {
		return fmt.Errorf("dump: %w", err)
	}

	// Save debug dump
	if f, err := os.Create(filepath.Join(os.TempDir(), "whatsapp_dump.json")); err == nil {
		var v interface{}
		json.Unmarshal([]byte(dump), &v)
		d, _ := json.MarshalIndent(v, "", "  ")
		f.Write(d)
		f.Close()
		fmt.Printf("[*] Debug dump saved to /tmp/whatsapp_dump.json\n")
	}

	injectJS := genInjectJS(dump, sd)

	var result string
	if err := chromedp.Run(ctx, chromedp.Evaluate(injectJS, &result)); err != nil {
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

func genInjectJS(_ string, sd *sessionData) string {
	noise := fmt.Sprintf("{pub:new Uint8Array(%s),priv:new Uint8Array(%s)}", bjs(sd.NoisePub), bjs(sd.NoisePriv))
	identity := fmt.Sprintf("{pub:new Uint8Array(%s),priv:new Uint8Array(%s)}", bjs(sd.IdentityPub), bjs(sd.IdentityPriv))
	sp := fmt.Sprintf("{keyId:%d,pub:new Uint8Array(%s),priv:new Uint8Array(%s),signature:new Uint8Array(%s)}", sd.SignedPreKeyID, bjs(sd.SignedPrePub), bjs(sd.SignedPrePriv), bjs(sd.SignedPreSig))
	rid := fmt.Sprintf("%d", sd.RegistrationID)
	adv := fmt.Sprintf("new Uint8Array(%s)", bjs(sd.AdvSecretKey))

	return fmt.Sprintf(`(async()=>{
const N=%s,I=%s,S=%s,R=%s,A=%s;
const dbs=await indexedDB.databases();let r=0;
let nDone=false,rDone=false;
for(const i of dbs){
  const db=await new Promise((res,rej)=>{const r=indexedDB.open(i.name);r.onsuccess=e=>res(e.target.result);r.onerror=e=>rej(e.target.error)});
  for(const sn of db.objectStoreNames){
    const tx=db.transaction(sn,'readwrite'),st=tx.objectStore(sn);
    await new Promise((res,rej)=>{
      const c=st.openCursor();
      c.onsuccess=e=>{
        const cur=e.target.result;
        if(!cur){res();return;}
        const v=cur.value;
        if(v&&typeof v==='object'){
          const hp=v.pub instanceof Uint8Array&&v.pub.length===32;
          const hr=v.priv instanceof Uint8Array&&v.priv.length===32;
          if(hp&&hr){
            if(!nDone){cur.update(N);nDone=true;}else cur.update(I);
            r++;
          }else if(typeof v.keyId==='number'&&hp&&hr&&v.signature instanceof Uint8Array&&v.signature.length){
            cur.update(S);r++;
          }else if(v instanceof Uint8Array&&v.length===32){
            cur.update(A);r++;
          }
        }else if(!rDone&&typeof v==='number'&&Number.isInteger(v)&&v>=0&&v<4294967296){
          cur.update(R);rDone=true;r++;
        }
        cur.continue();
      };
      c.onerror=e=>rej(e.target.error);
    });
  }
  db.close();
}
return "OK: "+r+" keys replaced";
})()`, noise, identity, sp, rid, adv)
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
