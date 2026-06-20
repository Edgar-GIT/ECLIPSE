package phone

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"programa/scripts/reportsdir"
	"programa/utils"
)

const (
	defaultPhoneInfoGaAPIBase = "http://localhost:5000/api"
	phoneInfoGaRepoURL        = "https://github.com/sundowndev/phoneinfoga.git"
	phoneInfoGaToolName       = "phoneinfoga"
	phoneInfoGaTimeout        = 45 * time.Second
	phoneInfoGaHealthTimeout  = 2 * time.Second
	phoneInfoGaBootTimeout    = 20 * time.Second
	phoneInfoGaMaxBody        = 8 * 1024 * 1024
	phoneInfoGaWorkers        = 3
)

var (
	phoneInfoGaServerMu      sync.Mutex
	phoneInfoGaServerStarted bool
	phoneInfoGaServerCmd     *exec.Cmd
	phoneInfoGaServerLog     *os.File
)

type phoneInfoGaRecord struct {
	ID             string                  `json:"id"`
	CreatedAt      time.Time               `json:"created_at"`
	Number         string                  `json:"number"`
	APIBaseURL     string                  `json:"api_base_url"`
	ResponseTimeMS float64                 `json:"response_time_ms"`
	StatusCode     int                     `json:"status_code,omitempty"`
	Error          string                  `json:"error,omitempty"`
	NumberInfo     *phoneInfoGaNumber      `json:"number_info,omitempty"`
	Scanners       []phoneInfoGaScannerRun `json:"scanners,omitempty"`
	ResultFile     string                  `json:"result_file,omitempty"`
}

type phoneInfoGaHistory struct {
	Records []phoneInfoGaRecord `json:"records"`
}

type phoneInfoGaNumber struct {
	Carrier       string `json:"carrier"`
	Country       string `json:"country"`
	CountryCode   int    `json:"countryCode"`
	E164          string `json:"e164"`
	International string `json:"international"`
	Local         string `json:"local"`
	RawLocal      string `json:"rawLocal"`
	Valid         bool   `json:"valid"`
}

type phoneInfoGaScanner struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type phoneInfoGaScannerList struct {
	Scanners []phoneInfoGaScanner `json:"scanners"`
}

type phoneInfoGaScannerRun struct {
	Name            string  `json:"name"`
	Description     string  `json:"description,omitempty"`
	Status          string  `json:"status"`
	DurationSeconds float64 `json:"duration_seconds"`
	StatusCode      int     `json:"status_code,omitempty"`
	Error           string  `json:"error,omitempty"`
	Result          any     `json:"result,omitempty"`
}

type phoneInfoGaCredentials map[string]string

type phoneInfoGaRunResponse struct {
	Result any    `json:"result"`
	Error  string `json:"error,omitempty"`
}

type phoneInfoGaAPIError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Success *bool  `json:"success,omitempty"`
}

func PhoneInformationMenu() {
	reader := bufio.NewReader(os.Stdin)
	for {
		utils.ClearTerminal()
		fmt.Printf("\n%s============ PHONE INFORMATION ============%s\n\n", utils.Blue, utils.Reset)
		fmt.Printf("%s[1]  - Phone-InfoGa%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[2]  - History%s\n", utils.Green, utils.Reset)
		utils.PrintReturnOption("3")

		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)
		input, readErr := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if readErr != nil && input == "" {
			return
		}

		switch input {
		case "1":
			runPhoneInfoGa(reader)
		case "2":
			ViewPhoneHistory()
		case "3", "0":
			return
		default:
			fmt.Printf("%sInvalid option.%s\n", utils.Yellow, utils.Reset)
			utils.WaitForEnter(reader)
		}
	}
}

func ViewPhoneHistory() {
	reader := bufio.NewReader(os.Stdin)
	for {
		utils.ClearTerminal()
		fmt.Printf("\n%s============ PHONE INFORMATION HISTORY ============%s\n\n", utils.Blue, utils.Reset)

		history, err := loadHistory()
		if err != nil {
			fmt.Printf("%s[!] Failed to load history: %v%s\n", utils.Red, err, utils.Reset)
			utils.WaitForEnter(reader)
			return
		}

		if len(history.Records) == 0 {
			fmt.Printf("%sNo phone lookups saved yet.%s\n\n", utils.Yellow, utils.Reset)
			fmt.Printf("%s[0] Return%s\n", utils.Green, utils.Reset)
			fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)
			line, _ := reader.ReadString('\n')
			if strings.TrimSpace(line) == "0" || strings.TrimSpace(line) == "" {
				return
			}
			continue
		}

		for i := len(history.Records) - 1; i >= 0; i-- {
			rec := history.Records[i]
			status := recordStatus(rec)
			target := rec.Number
			if rec.NumberInfo != nil && rec.NumberInfo.E164 != "" {
				target = rec.NumberInfo.E164
			}
			fmt.Printf("%s[%d]%s %s | %s | %s | %d scanner(s)\n",
				utils.Green,
				len(history.Records)-i,
				utils.Reset,
				rec.CreatedAt.Format("2006-01-02 15:04:05"),
				target,
				status,
				len(rec.Scanners),
			)
		}

		fmt.Printf("\n%s[Enter] View latest%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[#]     View by number%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[D]     Delete history%s\n", utils.Red, utils.Reset)
		fmt.Printf("%s[0]     Return%s\n", utils.Yellow, utils.Reset)
		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)

		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "0" {
			return
		}
		if strings.EqualFold(line, "d") {
			deleteHistory(reader)
			continue
		}

		selected := len(history.Records) - 1
		if line != "" {
			n, convErr := strconv.Atoi(line)
			if convErr != nil || n < 1 || n > len(history.Records) {
				fmt.Printf("%sInvalid selection.%s\n", utils.Yellow, utils.Reset)
				utils.WaitForEnter(reader)
				continue
			}
			selected = len(history.Records) - n
		}

		showHistoryRecord(reader, history.Records[selected])
	}
}

func runPhoneInfoGa(reader *bufio.Reader) {
	number := promptPhoneNumber(reader)
	if number == "" {
		return
	}
	credentials := ensurePhoneInfoGaCredentials(reader)

	fmt.Printf("\n%s[*] Preparing PhoneInfoga...%s\n", utils.Yellow, utils.Reset)
	rec := lookupNumber(context.Background(), number, credentials)
	displayRecord(rec)
	saveAndReportRecord(rec)
	utils.WaitForEnter(reader)
}

func promptPhoneNumber(reader *bufio.Reader) string {
	utils.ClearTerminal()
	fmt.Printf("\n%s============ PHONE-INFOGA ============%s\n\n", utils.Blue, utils.Reset)
	fmt.Printf("%sAPI:%s %s\n", utils.Green, utils.Reset, phoneInfoGaBaseURL())
	fmt.Printf("%sFormat:%s digits only with country code, for example 351912345678\n\n", utils.Green, utils.Reset)
	fmt.Printf("%sPhone number: %s", utils.Green, utils.Reset)
	line, _ := reader.ReadString('\n')
	number := normalizePhoneNumber(line)
	if number == "" {
		fmt.Printf("%sPhone number is required.%s\n", utils.Red, utils.Reset)
		utils.WaitForEnter(reader)
		return ""
	}
	if !isPhoneInfoGaNumber(number) {
		fmt.Printf("%sInvalid format. Use digits only with country code, for example 351912345678.%s\n", utils.Red, utils.Reset)
		utils.WaitForEnter(reader)
		return ""
	}
	return number
}

func lookupNumber(ctx context.Context, number string, credentials phoneInfoGaCredentials) phoneInfoGaRecord {
	baseURL, startedLocal, bootstrapErr := ensurePhoneInfoGaAPI(ctx)
	rec := phoneInfoGaRecord{
		ID:         fmt.Sprintf("%s_phoneinfoga_%s", time.Now().Format("20060102_150405"), safePhoneFilename(number)),
		CreatedAt:  time.Now(),
		Number:     number,
		APIBaseURL: baseURL,
	}
	if startedLocal {
		defer stopLocalPhoneInfoGa()
	}
	if bootstrapErr != nil {
		rec.Error = bootstrapErr.Error()
		return rec
	}

	fmt.Printf("%s[*] Querying PhoneInfoga API at %s...%s\n", utils.Blue, baseURL, utils.Reset)
	client := &http.Client{Timeout: phoneInfoGaTimeout}
	info, responseMS, statusCode, err := addNumber(ctx, client, baseURL, number)
	rec.ResponseTimeMS = responseMS
	rec.StatusCode = statusCode
	if err != nil {
		rec.Error = err.Error()
		return rec
	}

	rec.NumberInfo = &info
	if !info.Valid {
		rec.Error = "number is not valid according to PhoneInfoga"
		return rec
	}

	scanners, err := getScanners(ctx, client, baseURL)
	if err != nil {
		rec.Error = "scanner discovery failed: " + err.Error()
		return rec
	}
	if len(scanners) == 0 {
		rec.Error = "PhoneInfoga returned no scanners"
		return rec
	}

	scanNumber := info.International
	if scanNumber == "" {
		scanNumber = number
	}
	rec.Scanners = runScanners(ctx, client, baseURL, scanNumber, scanners, *rec.NumberInfo, credentials)
	return rec
}

func ensurePhoneInfoGaAPI(ctx context.Context) (string, bool, error) {
	baseURL := phoneInfoGaBaseURL()
	if err := phoneInfoGaHealth(ctx, baseURL); err == nil {
		return baseURL, false, nil
	}

	localBaseURL := defaultPhoneInfoGaAPIBase
	if baseURL != localBaseURL {
		fmt.Printf("%sConfigured PhoneInfoga API is unavailable. Falling back to local service.%s\n", utils.Yellow, utils.Reset)
	}
	started, err := startLocalPhoneInfoGa(ctx, localBaseURL)
	if err != nil {
		return localBaseURL, started, err
	}
	if err := waitPhoneInfoGaAPI(ctx, localBaseURL, phoneInfoGaBootTimeout); err != nil {
		if started {
			stopLocalPhoneInfoGa()
		}
		return localBaseURL, false, err
	}
	return localBaseURL, started, nil
}

func phoneInfoGaHealth(ctx context.Context, baseURL string) error {
	healthCtx, cancel := context.WithTimeout(ctx, phoneInfoGaHealthTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(healthCtx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ECLIPSE-PhoneInfoGa/1.0")

	resp, err := (&http.Client{Timeout: phoneInfoGaHealthTimeout}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("PhoneInfoga health check returned HTTP %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return err
	}
	var health struct {
		Success bool   `json:"success"`
		Version string `json:"version"`
		Commit  string `json:"commit"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(raw), &health); err != nil {
		return fmt.Errorf("unexpected PhoneInfoga health response")
	}
	if !health.Success && health.Version == "" && health.Commit == "" {
		return fmt.Errorf("unexpected PhoneInfoga health response")
	}
	return nil
}

func startLocalPhoneInfoGa(ctx context.Context, baseURL string) (bool, error) {
	phoneInfoGaServerMu.Lock()
	defer phoneInfoGaServerMu.Unlock()

	if err := phoneInfoGaHealth(ctx, baseURL); err == nil {
		return false, nil
	}
	if phoneInfoGaServerStarted {
		return false, nil
	}

	binaryPath, err := ensurePhoneInfoGaBinary()
	if err != nil {
		return false, err
	}

	port := phoneInfoGaPort(baseURL)
	if port == "" {
		port = "5000"
	}
	logPath := phoneInfoGaServerLogFile()
	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		return false, err
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return false, err
	}

	fmt.Printf("%s[*] Starting local PhoneInfoga API on port %s...%s\n", utils.Blue, port, utils.Reset)
	cmd := exec.Command(binaryPath, "serve", "--no-client", "-p", port)
	if dirExists(phoneInfoGaRepoDir()) {
		cmd.Dir = phoneInfoGaRepoDir()
	} else {
		cmd.Dir = reportsdir.WorkspaceRoot()
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = append(os.Environ(), "GIN_MODE=release")
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return false, fmt.Errorf("could not start PhoneInfoga: %w", err)
	}
	phoneInfoGaServerStarted = true
	phoneInfoGaServerCmd = cmd
	phoneInfoGaServerLog = logFile
	return true, nil
}

func stopLocalPhoneInfoGa() {
	phoneInfoGaServerMu.Lock()
	cmd := phoneInfoGaServerCmd
	logFile := phoneInfoGaServerLog
	phoneInfoGaServerCmd = nil
	phoneInfoGaServerLog = nil
	phoneInfoGaServerStarted = false
	phoneInfoGaServerMu.Unlock()

	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	if logFile != nil {
		_ = logFile.Close()
	}
}

func waitPhoneInfoGaAPI(ctx context.Context, baseURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := phoneInfoGaHealth(ctx, baseURL); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(350 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = errors.New("PhoneInfoga API did not become ready")
	}
	return fmt.Errorf("PhoneInfoga API did not become ready: %w", lastErr)
}

func ensurePhoneInfoGaBinary() (string, error) {
	if path, err := exec.LookPath(phoneInfoGaToolName); err == nil {
		return path, nil
	}

	repoDir := phoneInfoGaRepoDir()
	if !dirExists(repoDir) {
		if err := clonePhoneInfoGa(repoDir); err != nil {
			return "", err
		}
	}
	if !fileExists(filepath.Join(repoDir, "go.mod")) {
		return "", fmt.Errorf("%s exists but is not a valid PhoneInfoga repository", repoDir)
	}

	binaryPath := localPhoneInfoGaBinary()
	if fileExists(binaryPath) {
		return binaryPath, nil
	}
	if err := buildPhoneInfoGa(repoDir, binaryPath); err != nil {
		return "", err
	}
	return binaryPath, nil
}

func clonePhoneInfoGa(repoDir string) error {
	if err := os.MkdirAll(execToolsDir(), 0755); err != nil {
		return err
	}
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return fmt.Errorf("git is required to download PhoneInfoga")
	}
	fmt.Printf("%s[*] Downloading PhoneInfoga into %s...%s\n", utils.Blue, repoDir, utils.Reset)
	cmd := exec.Command(gitPath, "clone", "--depth=1", phoneInfoGaRepoURL, repoDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %w", err)
	}
	return nil
}

func buildPhoneInfoGa(repoDir, binaryPath string) error {
	goPath, err := exec.LookPath("go")
	if err != nil {
		return fmt.Errorf("go is required to build PhoneInfoga")
	}
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0755); err != nil {
		return err
	}
	if err := ensurePhoneInfoGaClientDist(repoDir); err != nil {
		return err
	}
	fmt.Printf("%s[*] Building PhoneInfoga...%s\n", utils.Blue, utils.Reset)
	cmd := exec.Command(goPath, "build", "-o", binaryPath, ".")
	cmd.Dir = repoDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"GOCACHE="+filepath.Join(repoDir, ".gocache"),
		"GOMODCACHE="+filepath.Join(repoDir, ".gomodcache"),
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("PhoneInfoga build failed: %w", err)
	}
	return nil
}

func ensurePhoneInfoGaClientDist(repoDir string) error {
	distDir := filepath.Join(repoDir, "web", "client", "dist")
	if err := os.MkdirAll(distDir, 0755); err != nil {
		return err
	}
	indexPath := filepath.Join(distDir, "index.html")
	if fileExists(indexPath) {
		return nil
	}
	return os.WriteFile(indexPath, []byte("<!doctype html><title>PhoneInfoga API</title>"), 0644)
}

func addNumber(ctx context.Context, client *http.Client, baseURL, number string) (phoneInfoGaNumber, float64, int, error) {
	var out phoneInfoGaNumber
	responseMS, statusCode, err := requestJSON(ctx, client, http.MethodPost, baseURL+"/v2/numbers", map[string]string{"number": number}, &out)
	return out, responseMS, statusCode, err
}

func getScanners(ctx context.Context, client *http.Client, baseURL string) ([]phoneInfoGaScanner, error) {
	var out phoneInfoGaScannerList
	_, _, err := requestJSON(ctx, client, http.MethodGet, baseURL+"/v2/scanners", nil, &out)
	if err != nil {
		return nil, err
	}
	sort.Slice(out.Scanners, func(i, j int) bool {
		return out.Scanners[i].Name < out.Scanners[j].Name
	})
	return out.Scanners, nil
}

func runScanners(ctx context.Context, client *http.Client, baseURL, number string, scanners []phoneInfoGaScanner, info phoneInfoGaNumber, credentials phoneInfoGaCredentials) []phoneInfoGaScannerRun {
	workers := phoneInfoGaWorkers
	if workers > len(scanners) {
		workers = len(scanners)
	}
	if workers < 1 {
		return nil
	}

	jobs := make(chan int)
	results := make([]phoneInfoGaScannerRun, len(scanners))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				scanner := scanners[idx]
				if reason := scannerSkipReason(scanner.Name, info, credentials); reason != "" {
					results[idx] = skippedScanner(scanner, reason)
					continue
				}
				results[idx] = runScanner(ctx, client, baseURL, number, scanner, credentials)
			}
		}()
	}

	for i := range scanners {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}

func runScanner(ctx context.Context, client *http.Client, baseURL, number string, scanner phoneInfoGaScanner, credentials phoneInfoGaCredentials) phoneInfoGaScannerRun {
	rec := phoneInfoGaScannerRun{
		Name:        scanner.Name,
		Description: scanner.Description,
		Status:      "ok",
	}

	endpoint := baseURL + "/v2/scanners/" + url.PathEscape(scanner.Name) + "/run"
	payload := map[string]any{
		"number":  number,
		"options": scannerOptions(scanner.Name, credentials),
	}
	var out phoneInfoGaRunResponse

	start := time.Now()
	_, statusCode, err := requestJSON(ctx, client, http.MethodPost, endpoint, payload, &out)
	rec.DurationSeconds = time.Since(start).Seconds()
	rec.StatusCode = statusCode
	if err != nil {
		rec.Status = "error"
		rec.Error = err.Error()
		return rec
	}
	if strings.TrimSpace(out.Error) != "" {
		rec.Status = "error"
		rec.Error = strings.TrimSpace(out.Error)
		return rec
	}
	rec.Result = out.Result
	return rec
}

func scannerSkipReason(scanner string, info phoneInfoGaNumber, credentials phoneInfoGaCredentials) string {
	switch strings.ToLower(strings.TrimSpace(scanner)) {
	case "numverify":
		if credentials["NUMVERIFY_API_KEY"] == "" {
			return "NUMVERIFY_API_KEY is not configured"
		}
	case "googlecse":
		if credentials["GOOGLE_API_KEY"] == "" || credentials["GOOGLECSE_CX"] == "" {
			return "GOOGLE_API_KEY and GOOGLECSE_CX are not configured"
		}
	case "ovh":
		if !isOVHSupportedCountryCode(info.CountryCode) {
			return fmt.Sprintf("OVH scanner does not support country code +%d", info.CountryCode)
		}
	}
	return ""
}

func scannerOptions(scanner string, credentials phoneInfoGaCredentials) map[string]any {
	options := map[string]any{}
	switch strings.ToLower(strings.TrimSpace(scanner)) {
	case "numverify":
		options["NUMVERIFY_API_KEY"] = credentials["NUMVERIFY_API_KEY"]
	case "googlecse":
		options["GOOGLE_API_KEY"] = credentials["GOOGLE_API_KEY"]
		options["GOOGLECSE_CX"] = credentials["GOOGLECSE_CX"]
		if credentials["GOOGLECSE_MAX_RESULTS"] != "" {
			options["GOOGLECSE_MAX_RESULTS"] = credentials["GOOGLECSE_MAX_RESULTS"]
		}
	}
	return options
}

func skippedScanner(scanner phoneInfoGaScanner, reason string) phoneInfoGaScannerRun {
	return phoneInfoGaScannerRun{
		Name:        scanner.Name,
		Description: scanner.Description,
		Status:      "skipped",
		Error:       reason,
	}
}

func isOVHSupportedCountryCode(code int) bool {
	switch code {
	case 33, 32, 44, 34, 41:
		return true
	default:
		return false
	}
}

func requestJSON(ctx context.Context, client *http.Client, method, endpoint string, payload any, dest any) (float64, int, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return 0, 0, err
		}
		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ECLIPSE-PhoneInfoGa/1.0")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	start := time.Now()
	resp, err := client.Do(req)
	responseMS := float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		return responseMS, 0, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, phoneInfoGaMaxBody))
	if err != nil {
		return responseMS, resp.StatusCode, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return responseMS, resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, apiErrorBody(raw))
	}

	if len(bytes.TrimSpace(raw)) > 0 && dest != nil {
		if err := json.Unmarshal(raw, dest); err != nil {
			return responseMS, resp.StatusCode, fmt.Errorf("invalid JSON response: %w", err)
		}
	}

	if msg := apiErrorMessage(raw); msg != "" {
		return responseMS, resp.StatusCode, errors.New(msg)
	}

	return responseMS, resp.StatusCode, nil
}

func displayRecord(rec phoneInfoGaRecord) {
	utils.ClearTerminal()
	fmt.Printf("\n%s============ PHONE-INFOGA RESULT ============%s\n\n", utils.Blue, utils.Reset)
	fmt.Printf("%sInput:%s %s\n", utils.Green, utils.Reset, rec.Number)
	fmt.Printf("%sAPI:%s %s\n", utils.Green, utils.Reset, rec.APIBaseURL)
	if rec.ResponseTimeMS > 0 {
		fmt.Printf("%sResponse:%s %.2f ms\n", utils.Green, utils.Reset, rec.ResponseTimeMS)
	}
	if rec.StatusCode > 0 {
		fmt.Printf("%sHTTP:%s %d\n", utils.Green, utils.Reset, rec.StatusCode)
	}
	if rec.Error != "" {
		fmt.Printf("\n%sStatus:%s %s\n", utils.Red, utils.Reset, rec.Error)
	}

	if rec.NumberInfo != nil {
		printNumberInfo(*rec.NumberInfo)
	}
	if len(rec.Scanners) > 0 {
		printScannerRuns(rec.Scanners)
	}
}

func printNumberInfo(info phoneInfoGaNumber) {
	fmt.Printf("\n%sNUMBER DATA%s\n", utils.Blue, utils.Reset)
	rows := [][2]string{
		{"Valid", yesNo(info.Valid)},
		{"E.164", fieldOrNA(info.E164)},
		{"International", fieldOrNA(info.International)},
		{"Local", fieldOrNA(info.Local)},
		{"Raw Local", fieldOrNA(info.RawLocal)},
		{"Country", fieldOrNA(info.Country)},
		{"Country Code", intOrNA(info.CountryCode)},
		{"Carrier", fieldOrNA(info.Carrier)},
	}
	printRows(rows)
}

func printScannerRuns(scanners []phoneInfoGaScannerRun) {
	fmt.Printf("\n%sSCANNERS%s\n", utils.Blue, utils.Reset)
	for _, scanner := range scanners {
		color := utils.Green
		switch scanner.Status {
		case "skipped":
			color = utils.Yellow
		case "ok":
			color = utils.Green
		default:
			color = utils.Red
		}
		fmt.Printf("%s%s%s | %s | %.2fs", color, scanner.Name, utils.Reset, strings.ToUpper(scanner.Status), scanner.DurationSeconds)
		if scanner.StatusCode > 0 {
			fmt.Printf(" | HTTP %d", scanner.StatusCode)
		}
		if scanner.Error != "" {
			fmt.Printf(" | %s", scanner.Error)
		}
		fmt.Println()
		if scanner.Result != nil && scanner.Error == "" {
			summary := scannerResultSummary(scanner.Result)
			if summary != "" {
				fmt.Printf("    %s\n", summary)
			}
		}
	}
}

func printRows(rows [][2]string) {
	width := 0
	for _, row := range rows {
		if len(row[0]) > width {
			width = len(row[0])
		}
	}
	for _, row := range rows {
		fmt.Printf("%s%s%s : %s\n", utils.Green, utils.PadOrTrim(row[0], width), utils.Reset, row[1])
	}
}

func showHistoryRecord(reader *bufio.Reader, rec phoneInfoGaRecord) {
	for {
		displayRecord(rec)
		if rec.ResultFile != "" {
			fmt.Printf("\n%sSaved:%s %s\n", utils.Green, utils.Reset, rec.ResultFile)
		}

		fmt.Printf("\n%sOptions:%s\n", utils.Blue, utils.Reset)
		fmt.Printf("%s[1] Show JSON%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[2] Refresh lookup%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[3] Open phone reports folder%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[0] Return%s\n", utils.Yellow, utils.Reset)
		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)

		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		switch line {
		case "1":
			pretty, err := json.MarshalIndent(rec, "", "  ")
			if err != nil {
				fmt.Printf("%sFailed to render JSON: %v%s\n", utils.Red, err, utils.Reset)
			} else {
				fmt.Printf("\n%s%s%s\n", utils.Blue, string(pretty), utils.Reset)
			}
			utils.WaitForEnter(reader)
		case "2":
			credentials := ensurePhoneInfoGaCredentials(reader)
			fresh := lookupNumber(context.Background(), rec.Number, credentials)
			displayRecord(fresh)
			saveAndReportRecord(fresh)
			utils.WaitForEnter(reader)
			rec = fresh
		case "3":
			if err := os.MkdirAll(phoneReportsDir(), 0755); err != nil {
				fmt.Printf("%s[!] %v%s\n", utils.Red, err, utils.Reset)
			} else if err := utils.OpenLocalFile(phoneReportsDir()); err != nil {
				fmt.Printf("%s[!] %v%s\n", utils.Red, err, utils.Reset)
			}
			utils.WaitForEnter(reader)
		case "0", "":
			return
		default:
			fmt.Printf("%sInvalid option.%s\n", utils.Yellow, utils.Reset)
			utils.WaitForEnter(reader)
		}
	}
}

func saveAndReportRecord(rec phoneInfoGaRecord) {
	if err := saveRecord(&rec); err != nil {
		fmt.Printf("\n%s[!] Failed to save phone lookup: %v%s\n", utils.Red, err, utils.Reset)
		writeActivity(fmt.Sprintf("phone lookup save failed for %s: %v", rec.Number, err))
		return
	}
	fmt.Printf("\n%s[OK] Result saved:%s %s\n", utils.Green, utils.Reset, rec.ResultFile)
	writeActivity(fmt.Sprintf("phone lookup finished for %s status=%d error=%s", rec.Number, rec.StatusCode, rec.Error))
}

func saveRecord(rec *phoneInfoGaRecord) error {
	if err := os.MkdirAll(resultsDir(), 0755); err != nil {
		return err
	}

	resultFile := filepath.Join(resultsDir(), rec.ID+".json")
	rec.ResultFile = resultFile
	pretty, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(resultFile, pretty, 0644); err != nil {
		return err
	}

	history, err := loadHistory()
	if err != nil {
		return err
	}
	history.Records = append(history.Records, *rec)
	return saveHistory(history)
}

func loadHistory() (phoneInfoGaHistory, error) {
	raw, err := os.ReadFile(historyFile())
	if err != nil {
		if os.IsNotExist(err) {
			return phoneInfoGaHistory{}, nil
		}
		return phoneInfoGaHistory{}, err
	}
	var history phoneInfoGaHistory
	if err := json.Unmarshal(raw, &history); err != nil {
		return phoneInfoGaHistory{}, err
	}
	return history, nil
}

func saveHistory(history phoneInfoGaHistory) error {
	if err := os.MkdirAll(filepath.Dir(historyFile()), 0755); err != nil {
		return err
	}
	pretty, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(historyFile(), pretty, 0644)
}

func deleteHistory(reader *bufio.Reader) {
	fmt.Printf("%sDelete phone lookup history? [y/N]: %s", utils.Yellow, utils.Reset)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	if line != "y" && line != "yes" && line != "s" && line != "sim" {
		return
	}
	if err := os.Remove(historyFile()); err != nil && !os.IsNotExist(err) {
		fmt.Printf("%s[!] %v%s\n", utils.Red, err, utils.Reset)
	} else {
		fmt.Printf("%sHistory deleted.%s\n", utils.Green, utils.Reset)
	}
	utils.WaitForEnter(reader)
}

func ensurePhoneInfoGaCredentials(reader *bufio.Reader) phoneInfoGaCredentials {
	credentials, exists, err := loadPhoneInfoGaCredentials()
	if err != nil {
		fmt.Printf("%s[!] Failed to load PhoneInfoga keys: %v%s\n", utils.Yellow, err, utils.Reset)
		return credentials
	}
	if exists {
		if missing := missingPhoneInfoGaCredentialGroups(credentials); len(missing) > 0 {
			fmt.Printf("%sOptional PhoneInfoga scanners disabled: %s. Edit %s to enable them.%s\n",
				utils.Yellow, strings.Join(missing, ", "), phoneInfoGaCredentialsFile(), utils.Reset)
		}
		return credentials
	}

	fmt.Printf("\n%s=== PHONEINFOGA API KEYS ===%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%sOptional scanners need external API keys:%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("%s- Numverify: NUMVERIFY_API_KEY from https://numverify.com/%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("%s- Google CSE: GOOGLE_API_KEY and GOOGLECSE_CX from Google Custom Search JSON API%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("%sLeave a value empty to skip that scanner. Keys will be saved to:%s %s\n\n", utils.Yellow, utils.Reset, phoneInfoGaCredentialsFile())

	credentials["NUMVERIFY_API_KEY"] = promptCredential(reader, "NUMVERIFY_API_KEY")
	credentials["GOOGLE_API_KEY"] = promptCredential(reader, "GOOGLE_API_KEY")
	credentials["GOOGLECSE_CX"] = promptCredential(reader, "GOOGLECSE_CX")
	if err := savePhoneInfoGaCredentials(credentials); err != nil {
		fmt.Printf("%s[!] Failed to save PhoneInfoga keys: %v%s\n", utils.Yellow, err, utils.Reset)
	} else {
		fmt.Printf("%s[OK] PhoneInfoga key file saved.%s\n", utils.Green, utils.Reset)
	}
	return credentials
}

func promptCredential(reader *bufio.Reader, key string) string {
	fmt.Printf("%s%s (Enter to skip): %s", utils.Green, key, utils.Reset)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func loadPhoneInfoGaCredentials() (phoneInfoGaCredentials, bool, error) {
	credentials := phoneInfoGaCredentials{}
	for _, key := range phoneInfoGaCredentialKeys() {
		credentials[key] = strings.TrimSpace(os.Getenv(key))
	}

	raw, err := os.ReadFile(phoneInfoGaCredentialsFile())
	if err != nil {
		if os.IsNotExist(err) {
			return credentials, false, nil
		}
		return credentials, false, err
	}

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if _, allowed := credentials[key]; !allowed {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if value != "" {
			credentials[key] = value
		}
	}
	return credentials, true, nil
}

func savePhoneInfoGaCredentials(credentials phoneInfoGaCredentials) error {
	if err := os.MkdirAll(filepath.Dir(phoneInfoGaCredentialsFile()), 0755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("NUMVERIFY_API_KEY=" + credentials["NUMVERIFY_API_KEY"] + "\n")
	b.WriteString("GOOGLE_API_KEY=" + credentials["GOOGLE_API_KEY"] + "\n")
	b.WriteString("GOOGLECSE_CX=" + credentials["GOOGLECSE_CX"] + "\n")
	b.WriteString("GOOGLECSE_MAX_RESULTS=" + credentials["GOOGLECSE_MAX_RESULTS"] + "\n")
	return os.WriteFile(phoneInfoGaCredentialsFile(), []byte(b.String()), 0600)
}

func phoneInfoGaCredentialKeys() []string {
	return []string{"NUMVERIFY_API_KEY", "GOOGLE_API_KEY", "GOOGLECSE_CX", "GOOGLECSE_MAX_RESULTS"}
}

func missingPhoneInfoGaCredentialGroups(credentials phoneInfoGaCredentials) []string {
	var missing []string
	if credentials["NUMVERIFY_API_KEY"] == "" {
		missing = append(missing, "numverify")
	}
	if credentials["GOOGLE_API_KEY"] == "" || credentials["GOOGLECSE_CX"] == "" {
		missing = append(missing, "googlecse")
	}
	return missing
}

func scannerResultSummary(result any) string {
	switch v := result.(type) {
	case nil:
		return ""
	case string:
		return fieldOrNA(v)
	case bool:
		return yesNo(v)
	case float64:
		return formatFloat(v)
	case []any:
		return fmt.Sprintf("%d item(s)", len(v))
	case map[string]any:
		return mapSummary(v)
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(raw)
	}
}

func recordStatus(rec phoneInfoGaRecord) string {
	if rec.Error != "" {
		return "ERROR"
	}
	if rec.NumberInfo != nil && !rec.NumberInfo.Valid {
		return "INVALID"
	}
	if len(rec.Scanners) == 0 {
		return "OK"
	}
	failed := 0
	skipped := 0
	for _, scanner := range rec.Scanners {
		switch scanner.Status {
		case "ok":
		case "skipped":
			skipped++
		default:
			failed++
		}
	}
	if failed == 0 {
		if skipped == len(rec.Scanners) {
			return "SKIPPED"
		}
		if skipped > 0 {
			return "PARTIAL"
		}
		return "OK"
	}
	if failed+skipped == len(rec.Scanners) && skipped == 0 {
		return "ERROR"
	}
	return "PARTIAL"
}

func mapSummary(data map[string]any) string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", fieldLabel(key), compactValue(data[key])))
		if len(parts) == 6 {
			break
		}
	}
	return strings.Join(parts, " | ")
}

func compactValue(value any) string {
	switch v := value.(type) {
	case nil:
		return "N/A"
	case string:
		return fieldOrNA(v)
	case bool:
		return yesNo(v)
	case float64:
		return formatFloat(v)
	case []any:
		return fmt.Sprintf("%d item(s)", len(v))
	case map[string]any:
		return fmt.Sprintf("%d field(s)", len(v))
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(raw)
	}
}

func apiErrorMessage(raw []byte) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return ""
	}
	var parsed phoneInfoGaAPIError
	if err := json.Unmarshal(raw, &parsed); err == nil {
		if msg := strings.TrimSpace(parsed.Error); msg != "" {
			return msg
		}
		if msg := strings.TrimSpace(parsed.Message); msg != "" {
			if parsed.Success != nil && !*parsed.Success {
				return msg
			}
		}
		if parsed.Success != nil && !*parsed.Success {
			return "remote service returned success=false"
		}
	}
	return ""
}

func apiErrorBody(raw []byte) string {
	raw = bytes.TrimSpace(raw)
	if msg := apiErrorMessage(raw); msg != "" {
		return msg
	}
	if len(raw) > 300 {
		raw = raw[:300]
	}
	if len(raw) == 0 {
		return "empty response"
	}
	return string(raw)
}

func phoneInfoGaBaseURL() string {
	base := strings.TrimSpace(os.Getenv("ECLIPSE_PHONEINFOGA_API_URL"))
	if base == "" {
		base = defaultPhoneInfoGaAPIBase
	}
	return strings.TrimRight(base, "/")
}

func normalizePhoneNumber(input string) string {
	input = strings.TrimSpace(input)
	replacer := strings.NewReplacer("+", "", " ", "", "\t", "", "-", "", "(", "", ")", "")
	return replacer.Replace(input)
}

func isPhoneInfoGaNumber(number string) bool {
	if len(number) < 7 || len(number) > 15 {
		return false
	}
	for _, r := range number {
		if r < '0' || r > '9' {
			return false
		}
	}
	return number[0] >= '1' && number[0] <= '9'
}

func safePhoneFilename(input string) string {
	input = strings.TrimSpace(strings.ToLower(input))
	input = strings.ReplaceAll(input, "+", "plus_")
	input = strings.ReplaceAll(input, " ", "_")
	input = utils.SanitizeForFilename(input)
	if input == "" {
		sum := md5.Sum([]byte(time.Now().String()))
		return hex.EncodeToString(sum[:])
	}
	return input
}

func fieldLabel(key string) string {
	key = strings.ReplaceAll(key, "_", " ")
	key = strings.ReplaceAll(key, "-", " ")
	return strings.ToUpper(key)
}

func fieldOrNA(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "N/A"
	}
	return value
}

func intOrNA(value int) string {
	if value == 0 {
		return "N/A"
	}
	return strconv.Itoa(value)
}

func formatFloat(value float64) string {
	if value == float64(int64(value)) {
		return fmt.Sprintf("%.0f", value)
	}
	return fmt.Sprintf("%v", value)
}

func yesNo(value bool) string {
	if value {
		return "YES"
	}
	return "NO"
}

func writeActivity(message string) {
	path := activityLogFile()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return
	}
	line := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), message)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line)
}

func phoneReportsDir() string {
	return filepath.Join(reportsdir.Root(), "phone")
}

func execToolsDir() string {
	return filepath.Join(reportsdir.WorkspaceRoot(), "exec_tools")
}

func phoneInfoGaRepoDir() string {
	return filepath.Join(execToolsDir(), phoneInfoGaToolName)
}

func localPhoneInfoGaBinary() string {
	name := phoneInfoGaToolName
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(phoneInfoGaRepoDir(), "bin", name)
}

func phoneInfoGaServerLogFile() string {
	return filepath.Join(phoneReportsDir(), "phoneinfoga_server.log")
}

func resultsDir() string {
	return filepath.Join(phoneReportsDir(), "results")
}

func historyFile() string {
	return filepath.Join(phoneReportsDir(), "history.json")
}

func activityLogFile() string {
	return filepath.Join(phoneReportsDir(), "activity.log")
}

func phoneInfoGaCredentialsFile() string {
	return filepath.Join(phoneReportsDir(), "phoneinfoga_keys.txt")
}

func phoneInfoGaPort(baseURL string) string {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	if port := parsed.Port(); port != "" {
		return port
	}
	switch parsed.Scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
