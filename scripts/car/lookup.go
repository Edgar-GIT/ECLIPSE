package car

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"programa/scripts/reportsdir"
	"programa/utils"
)

const (
	defaultLookupBase      = "https://vehicleinfobyterabaap.vercel.app/lookup"
	ptLookupBase           = "https://api.infomatricula.pt/informacao/fetch"
	firebaseAPIKey         = "AIzaSyC0ToM3KDiIgN_cvvRQNmS_0v9a3_oZM9Q"
	firebaseSignUpBase     = "https://identitytoolkit.googleapis.com/v1/accounts:signUp"
	firebaseSecureTokenURL = "https://securetoken.googleapis.com/v1/token"
	requestTimeout         = 15 * time.Second
)

type carLookupRecord struct {
	ID             string         `json:"id"`
	CreatedAt      time.Time      `json:"created_at"`
	Source         string         `json:"source"`
	Plate          string         `json:"plate"`
	Cached         bool           `json:"cached"`
	ResponseTimeMS float64        `json:"response_time_ms"`
	StatusCode     int            `json:"status_code,omitempty"`
	Error          string         `json:"error,omitempty"`
	Data           map[string]any `json:"data,omitempty"`
	ResultFile     string         `json:"result_file,omitempty"`
}

type carLookupHistory struct {
	Records []carLookupRecord `json:"records"`
}

type firebaseAuthCache struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

type firebaseSignUpResponse struct {
	IDToken      string `json:"idToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    string `json:"expiresIn"`
	Error        any    `json:"error,omitempty"`
}

type firebaseRefreshResponse struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    string `json:"expires_in"`
	Error        any    `json:"error,omitempty"`
}

func CarInformationMenu() {
	reader := bufio.NewReader(os.Stdin)
	for {
		utils.ClearTerminal()
		printMenu()

		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)
		input, readErr := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if readErr != nil && input == "" {
			return
		}

		switch input {
		case "1":
			defaultSearch(reader)
		case "2":
			ptPlate(reader)
		case "3":
			ViewCarHistory()
		case "4", "0":
			return
		default:
			fmt.Printf("%sInvalid option.%s\n", utils.Yellow, utils.Reset)
			utils.WaitForEnter(reader)
		}
	}
}

func ViewCarHistory() {
	reader := bufio.NewReader(os.Stdin)
	for {
		utils.ClearTerminal()
		fmt.Printf("\n%s============ CAR HISTORY ============%s\n\n", utils.Blue, utils.Reset)

		history, err := loadHistory()
		if err != nil {
			fmt.Printf("%s[!] Failed to load history: %v%s\n", utils.Red, err, utils.Reset)
			utils.WaitForEnter(reader)
			return
		}

		if len(history.Records) == 0 {
			fmt.Printf("%sNo car lookups saved yet.%s\n\n", utils.Yellow, utils.Reset)
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
			status := "OK"
			if rec.Error != "" {
				status = "ERROR"
			}
			fmt.Printf("%s[%d]%s %s | %s | %s | %s\n",
				utils.Green,
				len(history.Records)-i,
				utils.Reset,
				rec.CreatedAt.Format("2006-01-02 15:04:05"),
				strings.ToUpper(rec.Source),
				rec.Plate,
				status,
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

func printMenu() {
	fmt.Printf("\n%s============ CAR INFORMATION ============%s\n\n", utils.Blue, utils.Reset)
	fmt.Printf("%s[1]  - Default Vehicle Search%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[2]  - Portugal Plate Search%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[3]  - History%s\n", utils.Green, utils.Reset)
	utils.PrintReturnOption("4")
}

func defaultSearch(reader *bufio.Reader) {
	plate := promptPlate(reader, "Enter vehicle RC number")
	if plate == "" {
		return
	}

	rec := runLookup("default", plate)
	displayRecord(rec)
	saveAndReportRecord(rec)
	utils.WaitForEnter(reader)
}

func ptPlate(reader *bufio.Reader) {
	plate := promptPlate(reader, "Enter Portuguese plate")
	if plate == "" {
		return
	}

	rec := runLookup("pt", plate)
	displayRecord(rec)
	saveAndReportRecord(rec)
	utils.WaitForEnter(reader)
}

func promptPlate(reader *bufio.Reader, label string) string {
	utils.ClearTerminal()
	fmt.Printf("\n%s============ CAR LOOKUP ============%s\n\n", utils.Blue, utils.Reset)
	fmt.Printf("%s%s: %s", utils.Green, label, utils.Reset)
	line, _ := reader.ReadString('\n')
	plate := normalizePlate(line)
	if plate == "" {
		fmt.Printf("%sPlate is required.%s\n", utils.Red, utils.Reset)
		utils.WaitForEnter(reader)
		return ""
	}
	return plate
}

func runLookup(source, plate string) carLookupRecord {
	rec := carLookupRecord{
		ID:        fmt.Sprintf("%s_%s_%s", time.Now().Format("20060102_150405"), source, safeFilename(plate)),
		CreatedAt: time.Now(),
		Source:    source,
		Plate:     plate,
	}

	var data map[string]any
	var cached bool
	var responseMS float64
	var statusCode int
	var err error

	switch source {
	case "default":
		data, cached, responseMS, statusCode, err = fetchDefault(plate)
	case "pt":
		data, cached, responseMS, statusCode, err = fetchPT(plate)
	default:
		err = fmt.Errorf("unknown lookup source: %s", source)
	}

	rec.Cached = cached
	rec.ResponseTimeMS = responseMS
	rec.StatusCode = statusCode
	if err != nil {
		rec.Error = err.Error()
	}
	rec.Data = data
	return rec
}

func fetchDefault(plate string) (map[string]any, bool, float64, int, error) {
	cachePath := lookupCacheFile("default", plate)
	if data, responseMS, statusCode, ok := readCachedLookup(cachePath); ok {
		return data, true, responseMS, statusCode, nil
	}

	params := url.Values{}
	params.Set("rc", plate)
	reqURL := defaultLookupBase + "?" + params.Encode()
	data, responseMS, statusCode, err := requestJSON(reqURL, nil)
	if err != nil {
		return data, false, responseMS, statusCode, err
	}

	writeCachedLookup(cachePath, data, responseMS, statusCode)
	return data, false, responseMS, statusCode, nil
}

func fetchPT(plate string) (map[string]any, bool, float64, int, error) {
	cachePath := lookupCacheFile("pt", plate)
	if data, responseMS, statusCode, ok := readCachedLookup(cachePath); ok {
		return data, true, responseMS, statusCode, nil
	}

	token, err := infomatriculaBearer()
	if err != nil {
		return nil, false, 0, 0, err
	}

	params := url.Values{}
	params.Set("plate", plate)
	headers := map[string]string{
		"Authorization": "Bearer " + token,
		"Origin":        "https://infomatricula.pt",
		"Referer":       "https://infomatricula.pt/",
		"User-Agent":    "ECLIPSE-CarLookup/1.0",
	}

	data, responseMS, statusCode, err := requestJSON(ptLookupBase+"?"+params.Encode(), headers)
	if err != nil {
		return data, false, responseMS, statusCode, err
	}

	writeCachedLookup(cachePath, data, responseMS, statusCode)
	return data, false, responseMS, statusCode, nil
}

func requestJSON(reqURL string, headers map[string]string) (map[string]any, float64, int, error) {
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, 0, 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: requestTimeout}
	start := time.Now()
	resp, err := client.Do(req)
	responseMS := float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		return nil, responseMS, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, responseMS, resp.StatusCode, err
	}

	var data map[string]any
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &data); err != nil {
			return nil, responseMS, resp.StatusCode, fmt.Errorf("invalid JSON response: %w", err)
		}
	} else {
		data = map[string]any{}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return data, responseMS, resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	if msg, ok := errorMessageFromData(data); ok {
		return data, responseMS, resp.StatusCode, errors.New(msg)
	}

	return data, responseMS, resp.StatusCode, nil
}

func infomatriculaBearer() (string, error) {
	if token := strings.TrimSpace(os.Getenv("ECLIPSE_INFOMATRICULA_BEARER")); token != "" {
		return token, nil
	}

	cache := loadAuthCache()
	now := time.Now().Unix()
	if cache.IDToken != "" && cache.ExpiresAt > now+60 {
		return cache.IDToken, nil
	}
	if cache.RefreshToken != "" {
		if fresh, err := refreshFirebaseToken(cache.RefreshToken); err == nil && fresh.IDToken != "" {
			saveAuthCache(fresh)
			return fresh.IDToken, nil
		}
	}

	fresh, err := signInFirebaseAnonymous()
	if err != nil {
		return "", err
	}
	saveAuthCache(fresh)
	return fresh.IDToken, nil
}

func signInFirebaseAnonymous() (firebaseAuthCache, error) {
	body := []byte(`{"returnSecureToken":true}`)
	endpoint := firebaseSignUpBase + "?" + url.Values{"key": []string{firebaseAPIKey}}.Encode()
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return firebaseAuthCache{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: requestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return firebaseAuthCache{}, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return firebaseAuthCache{}, err
	}

	var parsed firebaseSignUpResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return firebaseAuthCache{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return firebaseAuthCache{}, fmt.Errorf("Firebase anonymous auth failed: HTTP %d", resp.StatusCode)
	}
	if parsed.IDToken == "" || parsed.RefreshToken == "" {
		return firebaseAuthCache{}, errors.New("Firebase anonymous auth returned no token")
	}

	return firebaseAuthCache{
		IDToken:      parsed.IDToken,
		RefreshToken: parsed.RefreshToken,
		ExpiresAt:    time.Now().Unix() + parseExpiresIn(parsed.ExpiresIn),
	}, nil
}

func refreshFirebaseToken(refreshToken string) (firebaseAuthCache, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	endpoint := firebaseSecureTokenURL + "?" + url.Values{"key": []string{firebaseAPIKey}}.Encode()
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return firebaseAuthCache{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: requestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return firebaseAuthCache{}, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return firebaseAuthCache{}, err
	}

	var parsed firebaseRefreshResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return firebaseAuthCache{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return firebaseAuthCache{}, fmt.Errorf("Firebase token refresh failed: HTTP %d", resp.StatusCode)
	}
	if parsed.IDToken == "" || parsed.RefreshToken == "" {
		return firebaseAuthCache{}, errors.New("Firebase token refresh returned no token")
	}

	return firebaseAuthCache{
		IDToken:      parsed.IDToken,
		RefreshToken: parsed.RefreshToken,
		ExpiresAt:    time.Now().Unix() + parseExpiresIn(parsed.ExpiresIn),
	}, nil
}

func parseExpiresIn(value string) int64 {
	seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || seconds <= 0 {
		return 3600
	}
	return seconds
}

func loadAuthCache() firebaseAuthCache {
	raw, err := os.ReadFile(authCacheFile())
	if err != nil {
		return firebaseAuthCache{}
	}
	var cache firebaseAuthCache
	if err := json.Unmarshal(raw, &cache); err != nil {
		return firebaseAuthCache{}
	}
	return cache
}

func saveAuthCache(cache firebaseAuthCache) {
	path := authCacheFile()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return
	}
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0600)
}

func displayRecord(rec carLookupRecord) {
	utils.ClearTerminal()
	title := "DEFAULT VEHICLE SEARCH"
	if rec.Source == "pt" {
		title = "PORTUGAL PLATE SEARCH"
	}

	fmt.Printf("\n%s============ %s ============%s\n\n", utils.Blue, title, utils.Reset)
	fmt.Printf("%sPlate:%s %s\n", utils.Green, utils.Reset, rec.Plate)
	fmt.Printf("%sCached:%s %s\n", utils.Green, utils.Reset, yesNo(rec.Cached))
	if rec.ResponseTimeMS > 0 {
		fmt.Printf("%sResponse:%s %.2f ms\n", utils.Green, utils.Reset, rec.ResponseTimeMS)
	}
	if rec.StatusCode > 0 {
		fmt.Printf("%sHTTP:%s %d\n", utils.Green, utils.Reset, rec.StatusCode)
	}

	if rec.Error != "" {
		fmt.Printf("\n%sERROR: %s%s\n", utils.Red, rec.Error, utils.Reset)
	}

	if len(rec.Data) == 0 {
		fmt.Printf("\n%sNo data returned.%s\n", utils.Yellow, utils.Reset)
		return
	}

	fmt.Printf("\n%sVEHICLE DATA OUTPUT%s\n", utils.Blue, utils.Reset)
	printDataTable(rec.Data)
}

func printDataTable(data map[string]any) {
	keys := make([]string, 0, len(data))
	for k := range data {
		if strings.HasPrefix(k, "_") {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		fmt.Printf("%sNo displayable fields.%s\n", utils.Yellow, utils.Reset)
		return
	}

	maxKey := 5
	for _, k := range keys {
		label := fieldLabel(k)
		if len(label) > maxKey {
			maxKey = len(label)
		}
	}
	if maxKey > 34 {
		maxKey = 34
	}

	for _, k := range keys {
		label := utils.PadOrTrim(fieldLabel(k), maxKey)
		fmt.Printf("%s%s%s : %s\n", utils.Green, label, utils.Reset, formatValue(data[k]))
	}
}

func showHistoryRecord(reader *bufio.Reader, rec carLookupRecord) {
	for {
		displayRecord(rec)
		if rec.ResultFile != "" {
			fmt.Printf("\n%sSaved:%s %s\n", utils.Green, utils.Reset, rec.ResultFile)
		}

		fmt.Printf("\n%sOptions:%s\n", utils.Blue, utils.Reset)
		fmt.Printf("%s[1] Show JSON%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[2] Refresh lookup%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[3] Open car reports folder%s\n", utils.Green, utils.Reset)
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
			fresh := runLookup(rec.Source, rec.Plate)
			displayRecord(fresh)
			saveAndReportRecord(fresh)
			utils.WaitForEnter(reader)
			rec = fresh
		case "3":
			if err := os.MkdirAll(carReportsDir(), 0755); err != nil {
				fmt.Printf("%s[!] %v%s\n", utils.Red, err, utils.Reset)
			} else if err := utils.OpenLocalFile(carReportsDir()); err != nil {
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

func saveAndReportRecord(rec carLookupRecord) {
	if err := saveRecord(&rec); err != nil {
		fmt.Printf("\n%s[!] Failed to save lookup: %v%s\n", utils.Red, err, utils.Reset)
		writeActivity(fmt.Sprintf("%s lookup save failed for %s: %v", rec.Source, rec.Plate, err))
		return
	}
	fmt.Printf("\n%s[OK] Result saved:%s %s\n", utils.Green, utils.Reset, rec.ResultFile)
	writeActivity(fmt.Sprintf("%s lookup finished for %s cached=%s status=%d error=%s", rec.Source, rec.Plate, yesNo(rec.Cached), rec.StatusCode, rec.Error))
}

func saveRecord(rec *carLookupRecord) error {
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

func loadHistory() (carLookupHistory, error) {
	raw, err := os.ReadFile(historyFile())
	if err != nil {
		if os.IsNotExist(err) {
			return carLookupHistory{}, nil
		}
		return carLookupHistory{}, err
	}
	var history carLookupHistory
	if err := json.Unmarshal(raw, &history); err != nil {
		return carLookupHistory{}, err
	}
	return history, nil
}

func saveHistory(history carLookupHistory) error {
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
	fmt.Printf("%sDelete car lookup history? [y/N]: %s", utils.Yellow, utils.Reset)
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

func readCachedLookup(path string) (map[string]any, float64, int, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, 0, false
	}
	var cached map[string]any
	if err := json.Unmarshal(raw, &cached); err != nil {
		return nil, 0, 0, false
	}
	responseMS := floatFromAny(cached["_response_time_ms"])
	statusCode := int(floatFromAny(cached["_status_code"]))
	return publicData(cached), responseMS, statusCode, true
}

func writeCachedLookup(path string, data map[string]any, responseMS float64, statusCode int) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return
	}
	cached := make(map[string]any, len(data)+3)
	for k, v := range data {
		cached[k] = v
	}
	cached["_response_time_ms"] = responseMS
	cached["_status_code"] = statusCode
	cached["_cached_at"] = time.Now().Format(time.RFC3339)
	pretty, err := json.MarshalIndent(cached, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, pretty, 0644)
}

func publicData(data map[string]any) map[string]any {
	out := make(map[string]any, len(data))
	for k, v := range data {
		if strings.HasPrefix(k, "_") {
			continue
		}
		out[k] = v
	}
	return out
}

func errorMessageFromData(data map[string]any) (string, bool) {
	if value, ok := data["error"]; ok {
		switch v := value.(type) {
		case bool:
			if v {
				return "remote service returned an error", true
			}
		case string:
			msg := strings.TrimSpace(v)
			if msg != "" && !strings.EqualFold(msg, "false") && !strings.EqualFold(msg, "no") {
				return msg, true
			}
		default:
			msg := strings.TrimSpace(formatValue(value))
			if msg != "" && msg != "{}" && msg != "[]" {
				return msg, true
			}
		}
	}
	if value, ok := data["message"]; ok {
		msg := strings.TrimSpace(formatValue(value))
		if strings.Contains(strings.ToLower(msg), "error") || strings.Contains(strings.ToLower(msg), "not found") {
			return msg, true
		}
	}
	return "", false
}

func formatValue(value any) string {
	switch v := value.(type) {
	case nil:
		return "N/A"
	case string:
		if strings.TrimSpace(v) == "" {
			return "N/A"
		}
		return v
	case float64:
		if v == float64(int64(v)) {
			return fmt.Sprintf("%.0f", v)
		}
		return fmt.Sprintf("%v", v)
	case bool:
		return yesNo(v)
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(raw)
	}
}

func fieldLabel(key string) string {
	key = strings.ReplaceAll(key, "_", " ")
	key = strings.ReplaceAll(key, "-", " ")
	return strings.ToUpper(key)
}

func normalizePlate(input string) string {
	input = strings.TrimSpace(strings.ToUpper(input))
	input = strings.ReplaceAll(input, " ", "")
	input = strings.ReplaceAll(input, "\t", "")
	return input
}

func safeFilename(input string) string {
	safe := utils.SanitizeForFilename(input)
	safe = strings.ReplaceAll(safe, " ", "_")
	if safe == "" {
		return "plate"
	}
	return safe
}

func lookupCacheFile(source, plate string) string {
	sum := md5.Sum([]byte(source + ":" + plate))
	return filepath.Join(cacheDir(), hex.EncodeToString(sum[:])+".json")
}

func floatFromAny(value any) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case string:
		f, _ := strconv.ParseFloat(v, 64)
		return f
	default:
		return 0
	}
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

func carReportsDir() string {
	return filepath.Join(reportsdir.Root(), "car")
}

func resultsDir() string {
	return filepath.Join(carReportsDir(), "results")
}

func cacheDir() string {
	return filepath.Join(carReportsDir(), "cache")
}

func historyFile() string {
	return filepath.Join(carReportsDir(), "history.json")
}

func authCacheFile() string {
	return filepath.Join(carReportsDir(), "infomatricula_auth.json")
}

func activityLogFile() string {
	return filepath.Join(carReportsDir(), "activity.log")
}
