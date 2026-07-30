package whatsapp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/chromedp/chromedp"
)

func DiscoverReferenceProfile(outDir string) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	userDir, err := os.MkdirTemp("", "whatsapp-ref-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(userDir)

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.UserDataDir(userDir), chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck, chromedp.WindowSize(1280, 900),
	)
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

	dumpDB(ctx, filepath.Join(outDir, "pre_pairing.json"))

	fmt.Println("\n[*] Waiting for pairing (up to 2 min)...")
	pc, pcCancel := context.WithTimeout(ctx, 120*time.Second)
	if err := chromedp.Run(pc, chromedp.WaitVisible("#app .two", chromedp.ByQuery)); err != nil {
		fmt.Println("[!] Timed out. Make sure you scanned the QR code.")
		pcCancel()
		return nil
	}
	pcCancel()
	time.Sleep(5 * time.Second)

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

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.UserDataDir(userDir), chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck, chromedp.WindowSize(1280, 900),
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	if err := chromedp.Run(ctx, chromedp.Navigate("https://web.whatsapp.com")); err != nil {
		return err
	}
	time.Sleep(4 * time.Second)

	var dump string
	if err := chromedp.Run(ctx, chromedp.Evaluate(jsDump, &dump)); err != nil {
		return fmt.Errorf("dump: %w", err)
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

func genInjectJS(dumpJSON string, sd *sessionData) string {
	type entry struct {
		dbName, storeName string
		keyIdx            int // index into the store's entries array
		kind              string // "noise", "identity", "spkey", "regid", "adv"
	}

	var dbs []struct {
		Name   string `json:"name"`
		Stores []struct {
			Name    string `json:"name"`
			Entries []struct {
				K interface{} `json:"k"`
				V interface{} `json:"v"`
			} `json:"entries"`
		} `json:"stores"`
	}
	if err := json.Unmarshal([]byte(dumpJSON), &dbs); err != nil {
		return `"dump parse error: ` + err.Error() + `"`
	}

	var matches []entry
	var noiseCount int

	for _, db := range dbs {
		for _, st := range db.Stores {
			for i, en := range st.Entries {
				vmap, ok := en.V.(map[string]interface{})
				if !ok {
					continue
				}
				// Check for NoiseKey/IdentityKey: object with pub+priv (both 32-byte buffers)
				pub, hasPub := vmap["pub"]
				priv, hasPriv := vmap["priv"]
				if hasPub && hasPriv {
					pubM, pubOk := pub.(map[string]interface{})
					privM, privOk := priv.(map[string]interface{})
					if pubOk && privOk && hasBuf32(pubM) && hasBuf32(privM) {
						noiseCount++
						kind := "noise"
						if noiseCount == 2 {
							kind = "identity"
						}
						matches = append(matches, entry{
							dbName: db.Name, storeName: st.Name, keyIdx: i, kind: kind,
						})
					}
				}
				// Check for SignedPreKey: object with keyId, pub, priv, signature
				if _, hasKID := vmap["keyId"]; hasKID {
					_, hasSig := vmap["signature"]
					_, hasPP := vmap["pub"]
					_, hasPr := vmap["priv"]
					if hasSig && hasPP && hasPr {
						matches = append(matches, entry{
							dbName: db.Name, storeName: st.Name, keyIdx: i, kind: "spkey",
						})
					}
				}
				// Check for bu32fer (AdvSecretKey)
				if hasBuf32(vmap) {
					matches = append(matches, entry{
						dbName: db.Name, storeName: st.Name, keyIdx: i, kind: "adv",
					})
				}
			}
		}
	}

	// Build JavaScript injection
	if len(matches) == 0 {
		return `"no key entries found in IndexedDB"`
	}

	js := "(async()=>{\n"
	js += "const k={noise:{pub:new Uint8Array(" + bjs(sd.NoisePub) + "),priv:new Uint8Array(" + bjs(sd.NoisePriv) + ")},"
	js += "id:{pub:new Uint8Array(" + bjs(sd.IdentityPub) + "),priv:new Uint8Array(" + bjs(sd.IdentityPriv) + ")},"
	js += "sp:{keyId:" + fmt.Sprintf("%d", sd.SignedPreKeyID) + ",pub:new Uint8Array(" + bjs(sd.SignedPrePub) + "),priv:new Uint8Array(" + bjs(sd.SignedPrePriv) + "),signature:new Uint8Array(" + bjs(sd.SignedPreSig) + ")},"
	js += "rid:" + fmt.Sprintf("%d", sd.RegistrationID) + ","
	js += "adv:new Uint8Array(" + bjs(sd.AdvSecretKey) + ")};\n"

	// Group by db/store for efficient transactions
	type byStore struct {
		db, store string
		entries   []entry
	}
	groups := make(map[string]*byStore)
	for _, m := range matches {
		key := m.dbName + "|" + m.storeName
		if _, ok := groups[key]; !ok {
			groups[key] = &byStore{db: m.dbName, store: m.storeName}
		}
		groups[key].entries = append(groups[key].entries, m)
	}

	for _, g := range groups {
		js += "{const db=await new Promise((res,rej)=>{const r=indexedDB.open(" + jsonQuote(g.db) + ");r.onsuccess=e=>res(e.target.result);r.onerror=e=>rej(e.target.error)});"
		js += "const tx=db.transaction(" + jsonQuote(g.store) + ",'readwrite');const st=tx.objectStore(" + jsonQuote(g.store) + ");"

		// Get all keys
		js += "const keys=await new Promise((res,rej)=>{const r=st.getAllKeys();r.onsuccess=e=>res(e.target.result);r.onerror=e=>rej(e.target.error)});\n"

		for _, m := range g.entries {
			var valJS string
			switch m.kind {
			case "noise":
				valJS = "k.noise"
			case "identity":
				valJS = "k.id"
			case "spkey":
				valJS = "k.sp"
			case "regid":
				valJS = "k.rid"
			case "adv":
				valJS = "k.adv"
			}
			js += "st.put(" + valJS + ",keys[" + fmt.Sprintf("%d", m.keyIdx) + "]);\n"
		}
		js += "await new Promise((res,rej)=>{tx.oncomplete=res;tx.onerror=rej});db.close()}\n"
	}

	js += `return "OK: ` + fmt.Sprintf("%d", len(matches)) + ` keys replaced"})()`

	return js
}

func hasBuf32(m map[string]interface{}) bool {
	b, ok := m["_b"]
	if !ok {
		return false
	}
	arr, ok := b.([]interface{})
	return ok && len(arr) == 32
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

func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
