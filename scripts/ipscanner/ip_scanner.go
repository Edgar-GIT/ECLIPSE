package ipscanner

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"programa/utils"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type IPInfo struct {
	IP           string    `json:"ip"`
	Status       string    `json:"status"`
	IPType       string    `json:"ip_type"`
	ScannedBy    string    `json:"scanned_by"`
	Hostname     string    `json:"hostname,omitempty"`
	ReverseDNS   string    `json:"reverse_dns,omitempty"`
	Continent    string    `json:"continent,omitempty"`
	CountryCode  string    `json:"country_code,omitempty"`
	Country      string    `json:"country,omitempty"`
	RegionCode   string    `json:"region_code,omitempty"`
	Region       string    `json:"region,omitempty"`
	City         string    `json:"city,omitempty"`
	District     string    `json:"district,omitempty"`
	ZIP          string    `json:"zip,omitempty"`
	Latitude     string    `json:"latitude,omitempty"`
	Longitude    string    `json:"longitude,omitempty"`
	Currency     string    `json:"currency,omitempty"`
	ISP          string    `json:"isp,omitempty"`
	Organization string    `json:"organization,omitempty"`
	ASN          string    `json:"asn,omitempty"`
	ASName       string    `json:"as_name,omitempty"`
	Mobile       string    `json:"mobile,omitempty"`
	Proxy        string    `json:"proxy,omitempty"`
	Hosting      string    `json:"hosting,omitempty"`
	Timezone     string    `json:"timezone,omitempty"`
	LastScanned  time.Time `json:"last_scanned"`
}

type ScanResults struct {
	ScanMode     string    `json:"scan_mode"`
	TotalScanned int       `json:"total_scanned"`
	Online       int       `json:"online"`
	Offline      int       `json:"offline"`
	ScannedAt    time.Time `json:"scanned_at"`
	IPs          []IPInfo  `json:"ips"`
}

type ScanHistory struct {
	Scans []ScanResults `json:"scans"`
}

const resultsFile = "ip_scan_results.json"

func isValidIPv4(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	return parsed != nil && parsed.To4() != nil
}

func classifyIPType(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil || parsed.To4() == nil {
		return "invalid"
	}
	if parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() {
		return "private"
	}
	return "public"
}

func buildRangeTargets(baseIP, startStr, endStr string) ([]string, error) {
	baseIP = strings.TrimSpace(baseIP)
	if baseIP == "" {
		return nil, fmt.Errorf("base IP cannot be empty")
	}

	parts := strings.Split(baseIP, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("base IP must be in format a.b.c")
	}

	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return nil, fmt.Errorf("base IP has invalid octets")
		}
	}

	start, err := strconv.Atoi(strings.TrimSpace(startStr))
	if err != nil || start < 0 || start > 255 {
		return nil, fmt.Errorf("invalid start range (0-255)")
	}

	end, err := strconv.Atoi(strings.TrimSpace(endStr))
	if err != nil || end < 0 || end > 255 {
		return nil, fmt.Errorf("invalid end range (0-255)")
	}

	if start > end {
		return nil, fmt.Errorf("start range cannot be greater than end range")
	}

	targets := make([]string, 0, end-start+1)
	for i := start; i <= end; i++ {
		targets = append(targets, fmt.Sprintf("%s.%d", baseIP, i))
	}

	return targets, nil
}

func getPublicIPv4() (string, error) {
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.ipify.org?format=text")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	publicIP := strings.TrimSpace(string(body))
	if !isValidIPv4(publicIP) {
		return "", fmt.Errorf("invalid public IPv4 returned: %s", publicIP)
	}

	return publicIP, nil
}

func pingIP(ip string) bool {
	var cmd *exec.Cmd

	if utils.DetectOS() == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "500", ip)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}

	err := cmd.Run()
	return err == nil
}

func getHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return "N/A"
	}
	return strings.TrimSuffix(names[0], ".")
}

func enrichGeoData(info *IPInfo) {
	// ip-api does not provide useful geolocation for private/local addresses.
	if info.IPType != "public" {
		info.ReverseDNS = "N/A"
		info.Continent = "N/A"
		info.CountryCode = "N/A"
		info.Country = "Private network"
		info.RegionCode = "N/A"
		info.Region = "N/A"
		info.City = "N/A"
		info.District = "N/A"
		info.ZIP = "N/A"
		info.Latitude = "N/A"
		info.Longitude = "N/A"
		info.Currency = "N/A"
		info.ISP = "N/A"
		info.Organization = "N/A"
		info.ASN = "N/A"
		info.ASName = "N/A"
		info.Mobile = "N/A"
		info.Proxy = "N/A"
		info.Hosting = "N/A"
		info.Timezone = "N/A"
		return
	}

	url := fmt.Sprintf(
		"http://ip-api.com/json/%s?fields=status,continent,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,currency,isp,org,as,asname,reverse,mobile,proxy,hosting",
		info.IP,
	)
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	var geoData map[string]interface{}
	if err := json.Unmarshal(body, &geoData); err != nil {
		return
	}

	if status, ok := geoData["status"].(string); ok && status == "success" {
		if continent, ok := geoData["continent"].(string); ok {
			info.Continent = continent
		}
		if countryCode, ok := geoData["countryCode"].(string); ok {
			info.CountryCode = countryCode
		}
		if country, ok := geoData["country"].(string); ok {
			info.Country = country
		}
		if regionCode, ok := geoData["region"].(string); ok {
			info.RegionCode = regionCode
		}
		if region, ok := geoData["regionName"].(string); ok {
			info.Region = region
		}
		if city, ok := geoData["city"].(string); ok {
			info.City = city
		}
		if district, ok := geoData["district"].(string); ok {
			info.District = district
		}
		if zip, ok := geoData["zip"].(string); ok {
			info.ZIP = zip
		}
		if lat, ok := geoData["lat"].(float64); ok {
			info.Latitude = fmt.Sprintf("%.6f", lat)
		}
		if lon, ok := geoData["lon"].(float64); ok {
			info.Longitude = fmt.Sprintf("%.6f", lon)
		}
		if isp, ok := geoData["isp"].(string); ok {
			info.ISP = isp
		}
		if org, ok := geoData["org"].(string); ok {
			info.Organization = org
		}
		if asn, ok := geoData["as"].(string); ok {
			info.ASN = asn
		}
		if asName, ok := geoData["asname"].(string); ok {
			info.ASName = asName
		}
		if reverse, ok := geoData["reverse"].(string); ok {
			info.ReverseDNS = reverse
		}
		if currency, ok := geoData["currency"].(string); ok {
			info.Currency = currency
		}
		if mobile, ok := geoData["mobile"].(bool); ok {
			info.Mobile = boolToLabel(mobile)
		}
		if proxy, ok := geoData["proxy"].(bool); ok {
			info.Proxy = boolToLabel(proxy)
		}
		if hosting, ok := geoData["hosting"].(bool); ok {
			info.Hosting = boolToLabel(hosting)
		}
		if tz, ok := geoData["timezone"].(string); ok {
			info.Timezone = tz
		}
	}

	time.Sleep(100 * time.Millisecond)
}

func scanSingleIP(ip string) IPInfo {
	info := IPInfo{
		IP:          ip,
		Status:      "offline",
		IPType:      classifyIPType(ip),
		ScannedBy:   "user",
		Hostname:    getHostname(ip),
		LastScanned: time.Now(),
	}

	if pingIP(ip) {
		info.Status = "online"
	}

	enrichGeoData(&info)
	return info
}

func boolToLabel(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func buildScanResults(mode string, allResults []IPInfo) ScanResults {
	online := 0
	offline := 0
	for _, info := range allResults {
		if info.Status == "online" {
			online++
		} else {
			offline++
		}
	}

	return ScanResults{
		ScanMode:     mode,
		TotalScanned: len(allResults),
		Online:       online,
		Offline:      offline,
		ScannedAt:    time.Now(),
		IPs:          allResults,
	}
}

func IpScanner() {
	utils.ClearTerminal()
	fmt.Printf("\n%s=== IP SCANNER ===%s\n\n", utils.Blue, utils.Reset)

	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("%sChoose scan mode:%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s[1] Range (e.g., 192.168.1.1-255)%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[2] Single IP%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[3] My public IP%s\n", utils.Green, utils.Reset)
	fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)

	modeInput, _ := reader.ReadString('\n')
	modeInput = strings.TrimSpace(modeInput)

	var mode string
	var targets []string
	var err error

	switch modeInput {
	case "1":
		mode = "range"
		fmt.Printf("%sEnter base IP (e.g., 192.168.1): %s", utils.Green, utils.Reset)
		baseIP, _ := reader.ReadString('\n')

		fmt.Printf("%sEnter start range (0-255): %s", utils.Green, utils.Reset)
		startStr, _ := reader.ReadString('\n')

		fmt.Printf("%sEnter end range (0-255): %s", utils.Green, utils.Reset)
		endStr, _ := reader.ReadString('\n')

		targets, err = buildRangeTargets(baseIP, startStr, endStr)
		if err != nil {
			fmt.Printf("\n%sInvalid range input: %v%s\n", utils.Red, err, utils.Reset)
			utils.WaitForEnter(reader)
			return
		}
	case "2":
		mode = "single-ip"
		fmt.Printf("%sEnter full IP (e.g., 8.8.8.8): %s", utils.Green, utils.Reset)
		inputIP, _ := reader.ReadString('\n')
		inputIP = strings.TrimSpace(inputIP)

		if !isValidIPv4(inputIP) {
			fmt.Printf("\n%sInvalid IPv4 address.%s\n", utils.Red, utils.Reset)
			utils.WaitForEnter(reader)
			return
		}

		targets = []string{inputIP}
	case "3":
		mode = "my-public-ip"
		publicIP, publicErr := getPublicIPv4()
		if publicErr != nil {
			fmt.Printf("\n%sCould not detect your public IP: %v%s\n", utils.Red, publicErr, utils.Reset)
			utils.WaitForEnter(reader)
			return
		}

		fmt.Printf("\n%sDetected public IP: %s%s\n", utils.Yellow, publicIP, utils.Reset)
		targets = []string{publicIP}
	default:
		fmt.Printf("\n%sInvalid option!%s\n", utils.Red, utils.Reset)
		utils.WaitForEnter(reader)
		return
	}

	fmt.Printf("\n%sScanning %d target(s)...%s\n\n", utils.Yellow, len(targets), utils.Reset)

	var wg sync.WaitGroup
	results := make(chan IPInfo, len(targets))
	semaphore := make(chan struct{}, 50)
	startTime := time.Now()

	for i, targetIP := range targets {
		wg.Add(1)
		go func(ip string, idx int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			fmt.Printf("%s[%d/%d] Scanning %s...%s\n", utils.Yellow, idx+1, len(targets), ip, utils.Reset)
			results <- scanSingleIP(ip)
		}(targetIP, i)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var allResults []IPInfo
	for info := range results {
		allResults = append(allResults, info)
	}

	duration := time.Since(startTime)
	scanResults := buildScanResults(mode, allResults)

	saveResults(scanResults)

	utils.ClearTerminal()

	displayResults(scanResults, duration)
	utils.WaitForEnter(reader)
}

func saveResults(results ScanResults) {
	history := ScanHistory{}
	existing, err := loadHistory()
	if err == nil {
		history = *existing
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Printf("%sError loading existing history: %v%s\n", utils.Red, err, utils.Reset)
		return
	}

	history.Scans = append(history.Scans, results)

	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		fmt.Printf("%sError saving results: %v%s\n", utils.Red, err, utils.Reset)
		return
	}

	err = os.WriteFile(resultsFile, data, 0644)
	if err != nil {
		fmt.Printf("%sError writing file: %v%s\n", utils.Red, err, utils.Reset)
		return
	}

	fmt.Printf("%s\n✓ Results saved to %s%s\n", utils.Green, resultsFile, utils.Reset)
}

func loadHistory() (*ScanHistory, error) {
	data, err := os.ReadFile(resultsFile)
	if err != nil {
		return nil, err
	}

	var history ScanHistory
	if err := json.Unmarshal(data, &history); err == nil && len(history.Scans) > 0 {
		return &history, nil
	}

	var single ScanResults
	if err := json.Unmarshal(data, &single); err == nil && len(single.IPs) > 0 {
		return &ScanHistory{Scans: []ScanResults{single}}, nil
	}

	return &ScanHistory{Scans: []ScanResults{}}, nil
}

func displayScanHistory(history *ScanHistory) {
	fmt.Printf("\n%sScan history (%d total):%s\n", utils.Blue, len(history.Scans), utils.Reset)
	for i, scan := range history.Scans {
		fmt.Printf("%s[%d] %s | mode=%s | total=%d | online=%d | offline=%d%s\n",
			utils.Yellow, i+1, scan.ScannedAt.Format("2006-01-02 15:04:05"),
			scan.ScanMode, scan.TotalScanned, scan.Online, scan.Offline, utils.Reset)
	}
}

func displayResults(results ScanResults, duration time.Duration) {
	fmt.Printf("\n%s╔═══════════════════════════════════════════════════════════════════════════╗%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s║                           SCAN STATISTICS                                 ║%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s╚═══════════════════════════════════════════════════════════════════════════╝%s\n", utils.Blue, utils.Reset)

	publicCount, privateCount := countByIPType(results.IPs)
	topCountries := topFromField(results.IPs, func(i IPInfo) string { return i.Country }, 3)
	topISPs := topFromField(results.IPs, func(i IPInfo) string { return i.ISP }, 3)

	fmt.Printf("\n%s  Mode:          %s%s%s\n", utils.Green, utils.Yellow, results.ScanMode, utils.Reset)
	fmt.Printf("%s  Total Scanned: %s%d%s\n", utils.Green, utils.Yellow, results.TotalScanned, utils.Reset)
	fmt.Printf("%s  Online:        %s%d%s\n", utils.Green, utils.Green, results.Online, utils.Reset)
	fmt.Printf("%s  Offline:       %s%d%s\n", utils.Green, utils.Red, results.Offline, utils.Reset)
	fmt.Printf("%s  Public IPs:    %s%d%s\n", utils.Green, utils.Yellow, publicCount, utils.Reset)
	fmt.Printf("%s  Private IPs:   %s%d%s\n", utils.Green, utils.Yellow, privateCount, utils.Reset)
	if duration > 0 {
		fmt.Printf("%s  Scan Duration: %s%.2fs%s\n", utils.Green, utils.Yellow, duration.Seconds(), utils.Reset)
	}
	fmt.Printf("%s  Scanned At:    %s%s%s\n\n", utils.Green, utils.Yellow, results.ScannedAt.Format("2006-01-02 15:04:05"), utils.Reset)
	fmt.Printf("%s  Top Countries: %s%s%s\n", utils.Green, utils.Yellow, strings.Join(topCountries, ", "), utils.Reset)
	fmt.Printf("%s  Top ISPs:      %s%s%s\n\n", utils.Green, utils.Yellow, strings.Join(topISPs, ", "), utils.Reset)

	fmt.Printf("%s╔═══════════════════════════════════════════════════════════════════════════╗%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s║                            SCANNED IP DETAILS                             ║%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s╚═══════════════════════════════════════════════════════════════════════════╝%s\n\n", utils.Blue, utils.Reset)

	for i, info := range results.IPs {
		statusColor := utils.Red
		if info.Status == "online" {
			statusColor = utils.Green
		}

		fmt.Printf("%s[%d] IP: %s%s%s | Status: %s%s%s | Type: %s%s%s\n", utils.Yellow, i+1, utils.Blue, info.IP, utils.Reset, statusColor, info.Status, utils.Reset, utils.Purple, info.IPType, utils.Reset)
		fmt.Printf("    IP scanned at: %s - %s\n", info.LastScanned.Format("2006-01-02 15:04:05"), info.ScannedBy)
		fmt.Printf("    Hostname:      %s\n", defaultValue(info.Hostname))
		fmt.Printf("    Reverse DNS:   %s\n", defaultValue(info.ReverseDNS))
		fmt.Printf("    ASN/AS Name:   %s | %s\n", defaultValue(info.ASN), defaultValue(info.ASName))
		fmt.Printf("    ISP:           %s\n", defaultValue(info.ISP))
		fmt.Printf("    Organization:  %s\n", defaultValue(info.Organization))
		fmt.Printf("    Continent:     %s\n", defaultValue(info.Continent))
		fmt.Printf("    Country:       %s (%s)\n", defaultValue(info.Country), defaultValue(info.CountryCode))
		fmt.Printf("    Region:        %s (%s)\n", defaultValue(info.Region), defaultValue(info.RegionCode))
		fmt.Printf("    City/District: %s / %s\n", defaultValue(info.City), defaultValue(info.District))
		fmt.Printf("    ZIP:           %s\n", defaultValue(info.ZIP))
		fmt.Printf("    Coordinates:   %s, %s\n", defaultValue(info.Latitude), defaultValue(info.Longitude))
		fmt.Printf("    Timezone:      %s\n", defaultValue(info.Timezone))
		fmt.Printf("    Currency:      %s\n", defaultValue(info.Currency))
		fmt.Printf("    Mobile/Proxy:  %s / %s\n", defaultValue(info.Mobile), defaultValue(info.Proxy))
		fmt.Printf("    Hosting:       %s\n", defaultValue(info.Hosting))
		fmt.Println()
	}
}

func countByIPType(ips []IPInfo) (int, int) {
	publicCount := 0
	privateCount := 0
	for _, ip := range ips {
		switch ip.IPType {
		case "public":
			publicCount++
		case "private":
			privateCount++
		}
	}
	return publicCount, privateCount
}

func topFromField(ips []IPInfo, field func(IPInfo) string, n int) []string {
	counts := map[string]int{}
	for _, ip := range ips {
		value := strings.TrimSpace(field(ip))
		if value == "" || value == "N/A" || value == "Private network" {
			continue
		}
		counts[value]++
	}

	if len(counts) == 0 {
		return []string{"N/A"}
	}

	type kv struct {
		Key   string
		Count int
	}
	var entries []kv
	for k, c := range counts {
		entries = append(entries, kv{Key: k, Count: c})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count == entries[j].Count {
			return entries[i].Key < entries[j].Key
		}
		return entries[i].Count > entries[j].Count
	})

	if n > len(entries) {
		n = len(entries)
	}

	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("%s(%d)", entries[i].Key, entries[i].Count))
	}
	return out
}

func defaultValue(v string) string {
	if strings.TrimSpace(v) == "" {
		return "N/A"
	}
	return v
}

func ViewScanResults() {
	utils.ClearTerminal()

	fmt.Printf("\n%s=== SCAN RESULTS ===%s\n\n", utils.Blue, utils.Reset)

	history, err := loadHistory()
	if err != nil || len(history.Scans) == 0 {
		fmt.Printf("%sNo scan results found. Run a scan first!%s\n", utils.Red, utils.Reset)
		reader := bufio.NewReader(os.Stdin)
		utils.WaitForEnter(reader)
		return
	}

	displayScanHistory(history)

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("\n%sChoose scan number to view (Enter = latest): %s", utils.Green, utils.Reset)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	selected := len(history.Scans) - 1
	if choice != "" {
		idx, convErr := strconv.Atoi(choice)
		if convErr != nil || idx < 1 || idx > len(history.Scans) {
			fmt.Printf("%sInvalid selection. Showing latest scan.%s\n", utils.Red, utils.Reset)
		} else {
			selected = idx - 1
		}
	}

	utils.ClearTerminal()

	fmt.Printf("\n%s=== SCAN DETAILS ===%s\n", utils.Blue, utils.Reset)
	displayResults(history.Scans[selected], 0)

	fmt.Printf("\n%sOptions:%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s[1] Refresh this scan (re-scan same IPs)%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[2] Delete all results%s\n", utils.Red, utils.Reset)
	fmt.Printf("%s[3] Return to menu%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("\n%sChoose option: %s", utils.Green, utils.Reset)

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	switch input {
	case "1":
		refreshResults(&history.Scans[selected])
	case "2":
		deleteResults()
	case "3":
		return
	default:
		fmt.Printf("%sInvalid option!%s\n", utils.Red, utils.Reset)
		time.Sleep(2 * time.Second)
	}
}

func refreshResults(oldResults *ScanResults) {
	utils.ClearTerminal()

	fmt.Printf("\n%s=== REFRESHING SCAN ===%s\n\n", utils.Blue, utils.Reset)

	var wg sync.WaitGroup
	results := make(chan IPInfo, len(oldResults.IPs))
	semaphore := make(chan struct{}, 50)
	startTime := time.Now()

	for i, oldInfo := range oldResults.IPs {
		wg.Add(1)
		go func(info IPInfo, idx int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			fmt.Printf("%s[%d/%d] Re-scanning %s...%s\n", utils.Yellow, idx+1, len(oldResults.IPs), info.IP, utils.Reset)
			results <- scanSingleIP(info.IP)
		}(oldInfo, i)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var allResults []IPInfo
	for info := range results {
		allResults = append(allResults, info)
	}

	duration := time.Since(startTime)
	scanResults := buildScanResults("refresh:"+oldResults.ScanMode, allResults)
	saveResults(scanResults)

	utils.ClearTerminal()

	displayResults(scanResults, duration)

	reader := bufio.NewReader(os.Stdin)
	utils.WaitForEnter(reader)
}

func deleteResults() {
	err := os.Remove(resultsFile)
	if err != nil {
		fmt.Printf("%sError deleting results: %v%s\n", utils.Red, err, utils.Reset)
	} else {
		fmt.Printf("%s✓ Results deleted successfully!%s\n", utils.Green, utils.Reset)
	}
	time.Sleep(2 * time.Second)
}
