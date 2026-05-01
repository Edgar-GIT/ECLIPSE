package ipscanner

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"programa/utils"
)

type IPInfo struct {
	IP              string           `json:"ip" xml:"ip,attr"`
	Status          string           `json:"status" xml:"status,attr"`
	DiscoveryMethod string           `json:"discovery_method,omitempty" xml:"discovery_method,omitempty"`
	IPType          string           `json:"ip_type" xml:"ip_type,omitempty"`
	AddressFamily   string           `json:"address_family" xml:"address_family,omitempty"`
	ScannedBy       string           `json:"scanned_by" xml:"scanned_by,omitempty"`
	Hostname        string           `json:"hostname,omitempty" xml:"hostname,omitempty"`
	ReverseDNS      string           `json:"reverse_dns,omitempty" xml:"reverse_dns,omitempty"`
	Continent       string           `json:"continent,omitempty" xml:"continent,omitempty"`
	CountryCode     string           `json:"country_code,omitempty" xml:"country_code,omitempty"`
	Country         string           `json:"country,omitempty" xml:"country,omitempty"`
	RegionCode      string           `json:"region_code,omitempty" xml:"region_code,omitempty"`
	Region          string           `json:"region,omitempty" xml:"region,omitempty"`
	City            string           `json:"city,omitempty" xml:"city,omitempty"`
	District        string           `json:"district,omitempty" xml:"district,omitempty"`
	ZIP             string           `json:"zip,omitempty" xml:"zip,omitempty"`
	Latitude        string           `json:"latitude,omitempty" xml:"latitude,omitempty"`
	Longitude       string           `json:"longitude,omitempty" xml:"longitude,omitempty"`
	Currency        string           `json:"currency,omitempty" xml:"currency,omitempty"`
	CurrencySymbol  string           `json:"currency_symbol,omitempty" xml:"currency_symbol,omitempty"`
	ISP             string           `json:"isp,omitempty" xml:"isp,omitempty"`
	Organization    string           `json:"organization,omitempty" xml:"organization,omitempty"`
	ASN             string           `json:"asn,omitempty" xml:"asn,omitempty"`
	ASName          string           `json:"as_name,omitempty" xml:"as_name,omitempty"`
	Mobile          string           `json:"mobile,omitempty" xml:"mobile,omitempty"`
	MobileCarrier   string           `json:"mobile_carrier,omitempty" xml:"mobile_carrier,omitempty"`
	Proxy           string           `json:"proxy,omitempty" xml:"proxy,omitempty"`
	ProxyType       string           `json:"proxy_type,omitempty" xml:"proxy_type,omitempty"`
	Hosting         string           `json:"hosting,omitempty" xml:"hosting,omitempty"`
	Timezone        string           `json:"timezone,omitempty" xml:"timezone,omitempty"`
	TimezoneOffset  string           `json:"timezone_offset,omitempty" xml:"timezone_offset,omitempty"`
	TTL             int              `json:"ttl,omitempty" xml:"ttl,omitempty"`
	LatencyMS       float64          `json:"latency_ms,omitempty" xml:"latency_ms,omitempty"`
	OSGuess         string           `json:"os_guess,omitempty" xml:"os_guess,omitempty"`
	OSConfidence    string           `json:"os_confidence,omitempty" xml:"os_confidence,omitempty"`
	RiskTags        []string         `json:"risk_tags,omitempty" xml:"risk_tags>tag,omitempty"`
	Scripts         []IPScriptResult `json:"scripts,omitempty" xml:"scripts>script,omitempty"`
	LastScanned     time.Time        `json:"last_scanned" xml:"last_scanned"`
}

type IPScriptResult struct {
	Name     string `json:"name" xml:"name,attr"`
	Status   string `json:"status" xml:"status,attr"`
	Output   string `json:"output,omitempty" xml:"output,omitempty"`
	Severity string `json:"severity,omitempty" xml:"severity,omitempty"`
}

type ScanResults struct {
	XMLName          xml.Name  `json:"-" xml:"ip_scan_results"`
	ScanMode         string    `json:"scan_mode" xml:"scan_mode,attr"`
	DiscoveryMethods []string  `json:"discovery_methods" xml:"discovery_methods>method,omitempty"`
	TotalScanned     int       `json:"total_scanned" xml:"total_scanned"`
	Online           int       `json:"online" xml:"online"`
	Offline          int       `json:"offline" xml:"offline"`
	TimedOut         int       `json:"timed_out,omitempty" xml:"timed_out,omitempty"`
	OutputFormat     string    `json:"output_format,omitempty" xml:"output_format,omitempty"`
	Concurrency      int       `json:"concurrency,omitempty" xml:"concurrency,omitempty"`
	TimeoutMS        int64     `json:"timeout_ms,omitempty" xml:"timeout_ms,omitempty"`
	RateLimit        int       `json:"rate_limit,omitempty" xml:"rate_limit,omitempty"`
	TimingTemplate   int       `json:"timing_template,omitempty" xml:"timing_template,omitempty"`
	SafetyNotes      []string  `json:"safety_notes,omitempty" xml:"safety_notes>note,omitempty"`
	ScannedAt        time.Time `json:"scanned_at" xml:"scanned_at"`
	IPs              []IPInfo  `json:"ips" xml:"ips>ip"`
}

type ScanHistory struct {
	Scans []ScanResults `json:"scans"`
}

type IPScannerOptions struct {
	Concurrency      int
	Timeout          time.Duration
	Retries          int
	RetryBackoff     time.Duration
	Delay            time.Duration
	RateLimit        int
	TimingTemplate   int
	OutputFormat     string
	DiscoveryMethods []string
	TCPPorts         []int
	UDPPorts         []int
	InterfaceName    string
	SourcePort       int
	TTL              int
	EnableGeo        bool
	EnableRDNS       bool
	EnableScripts    bool
	CacheResults     bool
	LogLevel         slog.Level
	SafetyNotes      []string
}

type hostObservation struct {
	Online  bool
	Method  string
	TTL     int
	Latency time.Duration
	Err     error
}

type simpleRateLimiter struct {
	ticker   *time.Ticker
	disabled bool
}

const (
	resultsFile     = "target/ip_scan_results.json"
	ipXMLFile       = "target/ip_scan_results.xml"
	ipGrepFile      = "target/ip_scan_results.grep"
	geoCacheMaxAge  = 30 * time.Minute
	hostCacheMaxAge = 5 * time.Minute
)

var (
	ipLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	geoCache = struct {
		sync.RWMutex
		values map[string]IPInfo
	}{values: map[string]IPInfo{}}

	hostCache = struct {
		sync.RWMutex
		values map[string]IPInfo
	}{values: map[string]IPInfo{}}
)

func isValidIPv4(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	return parsed != nil && parsed.To4() != nil
}

func isValidIP(ip string) bool {
	return net.ParseIP(strings.TrimSpace(ip)) != nil
}

func classifyIPType(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return "invalid"
	}
	if parsed.IsUnspecified() {
		return "unspecified"
	}
	if parsed.IsLoopback() {
		return "loopback"
	}
	if parsed.IsPrivate() {
		return "private"
	}
	if parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() {
		return "link-local"
	}
	if parsed.IsMulticast() {
		return "multicast"
	}
	if parsed.IsGlobalUnicast() {
		return "public"
	}
	return "reserved"
}

func addressFamily(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return "invalid"
	}
	if parsed.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
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
	return getPublicIPv4WithContext(context.Background())
}

func getPublicIPv4WithContext(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org?format=text", nil)
	if err != nil {
		return "", err
	}

	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
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
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()

	opts := defaultIPScannerOptions()
	opts.Timeout = 900 * time.Millisecond
	opts.Retries = 0
	opts.DiscoveryMethods = []string{"icmp", "tcp"}

	observation := discoverHost(ctx, ip, opts)
	return observation.Online
}

func getHostname(ip string) string {
	return reverseLookupWithRetry(context.Background(), ip, 2)
}

func defaultIPScannerOptions() IPScannerOptions {
	opts := IPScannerOptions{
		Concurrency:      64,
		Timeout:          1200 * time.Millisecond,
		Retries:          1,
		RetryBackoff:     150 * time.Millisecond,
		Delay:            0,
		RateLimit:        250,
		TimingTemplate:   3,
		OutputFormat:     "json",
		DiscoveryMethods: []string{"icmp", "tcp"},
		TCPPorts:         []int{22, 80, 443, 445, 3389},
		UDPPorts:         []int{53, 123},
		TTL:              64,
		EnableGeo:        true,
		EnableRDNS:       true,
		EnableScripts:    true,
		CacheResults:     true,
		LogLevel:         slog.LevelWarn,
	}
	return opts
}

func applyIPTimingTemplate(opts *IPScannerOptions) {
	switch clamp(opts.TimingTemplate, 0, 5) {
	case 0:
		opts.Concurrency = 1
		opts.Timeout = 5 * time.Second
		opts.Retries = 5
		opts.Delay = 5 * time.Second
		opts.RateLimit = 1
	case 1:
		opts.Concurrency = 4
		opts.Timeout = 3500 * time.Millisecond
		opts.Retries = 4
		opts.Delay = 1200 * time.Millisecond
		opts.RateLimit = 5
	case 2:
		opts.Concurrency = 16
		opts.Timeout = 2200 * time.Millisecond
		opts.Retries = 3
		opts.Delay = 250 * time.Millisecond
		opts.RateLimit = 40
	case 3:
		opts.Concurrency = 64
		opts.Timeout = 1200 * time.Millisecond
		opts.Retries = 1
		opts.Delay = 0
		opts.RateLimit = 250
	case 4:
		opts.Concurrency = 256
		opts.Timeout = 800 * time.Millisecond
		opts.Retries = 1
		opts.Delay = 0
		opts.RateLimit = 800
	case 5:
		opts.Concurrency = 512
		opts.Timeout = 450 * time.Millisecond
		opts.Retries = 0
		opts.Delay = 0
		opts.RateLimit = 1500
	}
	opts.TimingTemplate = clamp(opts.TimingTemplate, 0, 5)
}

func parseIPScannerOptions(raw string) IPScannerOptions {
	base := defaultIPScannerOptions()
	raw = strings.TrimSpace(raw)
	if raw == "" {
		configureIPLogger(base.LogLevel)
		return base
	}

	var (
		concurrency = base.Concurrency
		timeout     = base.Timeout
		retries     = base.Retries
		rateRaw     = fmt.Sprintf("%d", base.RateLimit)
		timing      = base.TimingTemplate
		output      = base.OutputFormat
		discovery   = strings.Join(base.DiscoveryMethods, ",")
		tcpPorts    = joinInts(base.TCPPorts)
		udpPorts    = joinInts(base.UDPPorts)
		iface       = base.InterfaceName
		sourcePort  = base.SourcePort
		ttl         = base.TTL
		noGeo       bool
		noRDNS      bool
		noScripts   bool
		noCache     bool
		logLevel    = "warn"
		decoy       string
		spoofIP     string
		mtu         int
	)

	fs := flag.NewFlagSet("ipscanner", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.IntVar(&concurrency, "concurrency", concurrency, "")
	fs.DurationVar(&timeout, "timeout", timeout, "")
	fs.IntVar(&retries, "retries", retries, "")
	fs.StringVar(&rateRaw, "rate", rateRaw, "")
	fs.IntVar(&timing, "T", timing, "")
	fs.StringVar(&output, "output-format", output, "")
	fs.StringVar(&discovery, "discovery", discovery, "")
	fs.StringVar(&tcpPorts, "tcp-probes", tcpPorts, "")
	fs.StringVar(&udpPorts, "udp-probes", udpPorts, "")
	fs.StringVar(&iface, "interface", iface, "")
	fs.IntVar(&sourcePort, "source-port", sourcePort, "")
	fs.IntVar(&ttl, "ttl", ttl, "")
	fs.BoolVar(&noGeo, "no-geo", false, "")
	fs.BoolVar(&noRDNS, "no-rdns", false, "")
	fs.BoolVar(&noScripts, "no-scripts", false, "")
	fs.BoolVar(&noCache, "no-cache", false, "")
	fs.StringVar(&logLevel, "log-level", logLevel, "")
	fs.StringVar(&decoy, "decoy", "", "")
	fs.StringVar(&spoofIP, "spoof-ip", "", "")
	fs.IntVar(&mtu, "mtu", 0, "")

	if err := fs.Parse(splitCLIFields(raw)); err != nil {
		ipLogger.Warn("invalid IP scanner options, using safe defaults", "error", err)
		configureIPLogger(base.LogLevel)
		return base
	}

	opts := base
	if timing != base.TimingTemplate {
		opts.TimingTemplate = timing
		applyIPTimingTemplate(&opts)
	}

	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "concurrency":
			opts.Concurrency = concurrency
		case "timeout":
			opts.Timeout = timeout
		case "retries":
			opts.Retries = retries
		case "rate":
			opts.RateLimit = parseRateLimit(rateRaw, opts.RateLimit)
		case "output-format":
			opts.OutputFormat = strings.ToLower(strings.TrimSpace(output))
		case "discovery":
			opts.DiscoveryMethods = parseDiscoveryMethods(discovery)
		case "tcp-probes":
			opts.TCPPorts = parsePorts(tcpPorts)
		case "udp-probes":
			opts.UDPPorts = parsePorts(udpPorts)
		case "interface":
			opts.InterfaceName = strings.TrimSpace(iface)
		case "source-port":
			opts.SourcePort = sourcePort
		case "ttl":
			opts.TTL = ttl
		case "no-geo":
			opts.EnableGeo = !noGeo
		case "no-rdns":
			opts.EnableRDNS = !noRDNS
		case "no-scripts":
			opts.EnableScripts = !noScripts
		case "no-cache":
			opts.CacheResults = !noCache
		case "log-level":
			opts.LogLevel = parseSlogLevel(logLevel)
		}
	})

	if decoy != "" || spoofIP != "" || mtu > 0 {
		opts.SafetyNotes = append(opts.SafetyNotes, "Decoy, spoofing, and fragmentation flags were accepted for compatibility but not executed in this defensive scanner build.")
	}
	if opts.SourcePort > 0 && opts.Concurrency > 1 {
		opts.SafetyNotes = append(opts.SafetyNotes, "A fixed source port can conflict under concurrency; reduce --concurrency to 1 if the operating system rejects binds.")
	}

	opts.Concurrency = clamp(opts.Concurrency, 1, 4096)
	opts.Retries = clamp(opts.Retries, 0, 10)
	opts.SourcePort = clamp(opts.SourcePort, 0, 65535)
	opts.TTL = clamp(opts.TTL, 1, 255)
	if opts.Timeout < 100*time.Millisecond {
		opts.Timeout = 100 * time.Millisecond
	}
	if opts.OutputFormat == "" {
		opts.OutputFormat = "json"
	}
	if opts.OutputFormat != "json" && opts.OutputFormat != "xml" && opts.OutputFormat != "grep" && opts.OutputFormat != "all" {
		opts.OutputFormat = "json"
	}
	if len(opts.DiscoveryMethods) == 0 {
		opts.DiscoveryMethods = []string{"icmp", "tcp"}
	}
	if len(opts.TCPPorts) == 0 {
		opts.TCPPorts = []int{22, 80, 443, 445, 3389}
	}
	if len(opts.UDPPorts) == 0 {
		opts.UDPPorts = []int{53, 123}
	}

	configureIPLogger(opts.LogLevel)
	return opts
}

func configureIPLogger(level slog.Level) {
	ipLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func parseSlogLevel(value string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "error":
		return slog.LevelError
	default:
		return slog.LevelWarn
	}
}

func parseRateLimit(value string, fallback int) int {
	clean := strings.ToLower(strings.TrimSpace(value))
	clean = strings.TrimSuffix(clean, "/sec")
	clean = strings.TrimSuffix(clean, "/s")
	clean = strings.TrimSuffix(clean, "pps")
	clean = strings.TrimSpace(clean)
	rate, err := strconv.Atoi(clean)
	if err != nil || rate < 0 {
		return fallback
	}
	return rate
}

func splitCLIFields(raw string) []string {
	fields := make([]string, 0)
	var current strings.Builder
	inQuote := rune(0)
	escaped := false

	for _, r := range raw {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case inQuote != 0:
			if r == inQuote {
				inQuote = 0
			} else {
				current.WriteRune(r)
			}
		case r == '\'' || r == '"':
			inQuote = r
		case r == ' ' || r == '\t' || r == '\n':
			if current.Len() > 0 {
				fields = append(fields, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		fields = append(fields, current.String())
	}
	return fields
}

func parseDiscoveryMethods(value string) []string {
	aliases := map[string]string{
		"-sn": "sn", "sn": "sn",
		"-pe": "icmp", "pe": "icmp", "icmp": "icmp", "echo": "icmp",
		"-pp": "timestamp", "pp": "timestamp", "timestamp": "timestamp",
		"-pm": "netmask", "pm": "netmask", "netmask": "netmask",
		"-ps": "tcp", "ps": "tcp", "syn": "tcp", "tcp": "tcp",
		"-pa": "ack", "pa": "ack", "ack": "ack",
		"-pu": "udp", "pu": "udp", "udp": "udp",
		"-py": "sctp", "py": "sctp", "sctp": "sctp",
		"arp": "arp",
	}

	var out []string
	seen := map[string]struct{}{}
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '+' }) {
		key := strings.ToLower(strings.TrimSpace(part))
		if key == "" {
			continue
		}
		method, ok := aliases[key]
		if !ok {
			continue
		}
		if method == "sn" {
			method = "icmp"
		}
		if _, exists := seen[method]; exists {
			continue
		}
		seen[method] = struct{}{}
		out = append(out, method)
	}
	return out
}

func parsePorts(value string) []int {
	seen := map[int]struct{}{}
	var ports []int
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, errA := strconv.Atoi(strings.TrimSpace(bounds[0]))
			end, errB := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if errA != nil || errB != nil {
				continue
			}
			if start > end {
				start, end = end, start
			}
			for p := start; p <= end; p++ {
				if p < 1 || p > 65535 {
					continue
				}
				if _, ok := seen[p]; !ok {
					seen[p] = struct{}{}
					ports = append(ports, p)
				}
			}
			continue
		}
		port, err := strconv.Atoi(part)
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		if _, ok := seen[port]; !ok {
			seen[port] = struct{}{}
			ports = append(ports, port)
		}
	}
	sort.Ints(ports)
	return ports
}

func joinInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(value))
	}
	return strings.Join(parts, ",")
}

func newSimpleRateLimiter(eventsPerSecond int) *simpleRateLimiter {
	if eventsPerSecond <= 0 {
		return &simpleRateLimiter{disabled: true}
	}
	interval := time.Second / time.Duration(eventsPerSecond)
	if interval < time.Microsecond {
		interval = time.Microsecond
	}
	return &simpleRateLimiter{ticker: time.NewTicker(interval)}
}

func (r *simpleRateLimiter) Wait(ctx context.Context) error {
	if r == nil || r.disabled {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.ticker.C:
		return nil
	}
}

func (r *simpleRateLimiter) Stop() {
	if r != nil && r.ticker != nil {
		r.ticker.Stop()
	}
}

func enrichGeoData(info *IPInfo) {
	enrichGeoDataWithContext(context.Background(), info, defaultIPScannerOptions())
}

func enrichGeoDataWithContext(ctx context.Context, info *IPInfo, opts IPScannerOptions) {
	if !opts.EnableGeo {
		return
	}

	if info.IPType != "public" {
		fillPrivateGeoDefaults(info)
		return
	}

	geoCache.RLock()
	cached, ok := geoCache.values[info.IP]
	geoCache.RUnlock()
	if ok && time.Since(cached.LastScanned) <= geoCacheMaxAge {
		copyGeoFields(info, cached)
		return
	}

	url := fmt.Sprintf(
		"http://ip-api.com/json/%s?fields=status,continent,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting",
		info.IP,
	)

	var lastErr error
	for attempt := 0; attempt <= opts.Retries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return
		}

		client := http.Client{Timeout: minDuration(opts.Timeout+time.Second, 6*time.Second)}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			sleepBackoff(ctx, opts.RetryBackoff, attempt)
			continue
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			sleepBackoff(ctx, opts.RetryBackoff, attempt)
			continue
		}

		var geoData map[string]interface{}
		if err := json.Unmarshal(body, &geoData); err != nil {
			lastErr = err
			sleepBackoff(ctx, opts.RetryBackoff, attempt)
			continue
		}

		if status, ok := geoData["status"].(string); !ok || status != "success" {
			lastErr = fmt.Errorf("geo provider returned non-success status")
			sleepBackoff(ctx, opts.RetryBackoff, attempt)
			continue
		}

		applyGeoData(info, geoData)
		geoCache.Lock()
		geoCache.values[info.IP] = *info
		geoCache.Unlock()
		return
	}

	if lastErr != nil {
		ipLogger.Debug("geo enrichment failed", "ip", info.IP, "error", lastErr)
	}
}

func fillPrivateGeoDefaults(info *IPInfo) {
	info.ReverseDNS = defaultIfEmpty(info.ReverseDNS, "N/A")
	info.Continent = "N/A"
	info.CountryCode = "N/A"
	info.Country = "Private or non-public network"
	info.RegionCode = "N/A"
	info.Region = "N/A"
	info.City = "N/A"
	info.District = "N/A"
	info.ZIP = "N/A"
	info.Latitude = "N/A"
	info.Longitude = "N/A"
	info.Currency = "N/A"
	info.CurrencySymbol = "N/A"
	info.ISP = "N/A"
	info.Organization = "N/A"
	info.ASN = "N/A"
	info.ASName = "N/A"
	info.Mobile = "N/A"
	info.MobileCarrier = "N/A"
	info.Proxy = "N/A"
	info.ProxyType = "N/A"
	info.Hosting = "N/A"
	info.Timezone = "N/A"
	info.TimezoneOffset = "N/A"
}

func copyGeoFields(dst *IPInfo, src IPInfo) {
	dst.ReverseDNS = defaultIfEmpty(dst.ReverseDNS, src.ReverseDNS)
	dst.Continent = src.Continent
	dst.CountryCode = src.CountryCode
	dst.Country = src.Country
	dst.RegionCode = src.RegionCode
	dst.Region = src.Region
	dst.City = src.City
	dst.District = src.District
	dst.ZIP = src.ZIP
	dst.Latitude = src.Latitude
	dst.Longitude = src.Longitude
	dst.Currency = src.Currency
	dst.CurrencySymbol = src.CurrencySymbol
	dst.ISP = src.ISP
	dst.Organization = src.Organization
	dst.ASN = src.ASN
	dst.ASName = src.ASName
	dst.Mobile = src.Mobile
	dst.MobileCarrier = src.MobileCarrier
	dst.Proxy = src.Proxy
	dst.ProxyType = src.ProxyType
	dst.Hosting = src.Hosting
	dst.Timezone = src.Timezone
	dst.TimezoneOffset = src.TimezoneOffset
}

func applyGeoData(info *IPInfo, geoData map[string]interface{}) {
	info.Continent = stringField(geoData, "continent")
	info.CountryCode = stringField(geoData, "countryCode")
	info.Country = stringField(geoData, "country")
	info.RegionCode = stringField(geoData, "region")
	info.Region = stringField(geoData, "regionName")
	info.City = stringField(geoData, "city")
	info.District = stringField(geoData, "district")
	info.ZIP = stringField(geoData, "zip")
	info.ISP = stringField(geoData, "isp")
	info.Organization = stringField(geoData, "org")
	info.ASN = stringField(geoData, "as")
	info.ASName = stringField(geoData, "asname")
	info.ReverseDNS = defaultIfEmpty(info.ReverseDNS, stringField(geoData, "reverse"))
	info.Currency = stringField(geoData, "currency")
	info.CurrencySymbol = currencySymbol(info.Currency)
	info.Timezone = stringField(geoData, "timezone")

	if lat, ok := geoData["lat"].(float64); ok {
		info.Latitude = fmt.Sprintf("%.6f", lat)
	}
	if lon, ok := geoData["lon"].(float64); ok {
		info.Longitude = fmt.Sprintf("%.6f", lon)
	}
	if offset, ok := geoData["offset"].(float64); ok {
		info.TimezoneOffset = formatTimezoneOffset(int(offset))
	}
	if mobile, ok := geoData["mobile"].(bool); ok {
		info.Mobile = boolToLabel(mobile)
		if mobile {
			info.MobileCarrier = defaultIfEmpty(info.Organization, info.ISP)
		} else {
			info.MobileCarrier = "N/A"
		}
	}
	if proxy, ok := geoData["proxy"].(bool); ok {
		info.Proxy = boolToLabel(proxy)
		if proxy {
			info.ProxyType = inferProxyType(info)
		} else {
			info.ProxyType = "none"
		}
	}
	if hosting, ok := geoData["hosting"].(bool); ok {
		info.Hosting = boolToLabel(hosting)
	}
}

func stringField(values map[string]interface{}, key string) string {
	if value, ok := values[key].(string); ok {
		return value
	}
	return ""
}

func formatTimezoneOffset(seconds int) string {
	sign := "+"
	if seconds < 0 {
		sign = "-"
		seconds = -seconds
	}
	hours := seconds / 3600
	minutes := (seconds % 3600) / 60
	return fmt.Sprintf("%s%02d:%02d", sign, hours, minutes)
}

func inferProxyType(info *IPInfo) string {
	text := strings.ToLower(info.ISP + " " + info.Organization + " " + info.ASName)
	switch {
	case strings.Contains(text, "vpn"):
		return "vpn"
	case strings.Contains(text, "tor"):
		return "tor-exit-or-relay"
	case strings.Contains(text, "hosting") || strings.Contains(text, "cloud") || strings.Contains(text, "data"):
		return "datacenter-proxy"
	default:
		return "generic-proxy"
	}
}

func currencySymbol(code string) string {
	switch strings.ToUpper(strings.TrimSpace(code)) {
	case "USD":
		return "$"
	case "EUR":
		return "EUR"
	case "GBP":
		return "GBP"
	case "JPY":
		return "JPY"
	case "CAD":
		return "C$"
	case "AUD":
		return "A$"
	case "BRL":
		return "R$"
	case "CHF":
		return "CHF"
	case "CNY":
		return "CNY"
	default:
		if strings.TrimSpace(code) == "" {
			return ""
		}
		return strings.ToUpper(strings.TrimSpace(code))
	}
}

func scanSingleIP(ip string) IPInfo {
	return scanSingleIPWithOptions(context.Background(), ip, defaultIPScannerOptions())
}

func scanSingleIPWithOptions(ctx context.Context, ip string, opts IPScannerOptions) IPInfo {
	now := time.Now()
	normalizedIP := strings.TrimSpace(ip)

	if opts.CacheResults {
		hostCache.RLock()
		cached, ok := hostCache.values[normalizedIP]
		hostCache.RUnlock()
		if ok && time.Since(cached.LastScanned) <= hostCacheMaxAge {
			return cached
		}
	}

	info := IPInfo{
		IP:            normalizedIP,
		Status:        "offline",
		IPType:        classifyIPType(normalizedIP),
		AddressFamily: addressFamily(normalizedIP),
		ScannedBy:     "user",
		LastScanned:   now,
	}

	if !isValidIP(normalizedIP) {
		info.Status = "invalid"
		return info
	}

	observation := discoverHost(ctx, normalizedIP, opts)
	if observation.Online {
		info.Status = "online"
		info.DiscoveryMethod = observation.Method
		info.TTL = observation.TTL
		if observation.Latency > 0 {
			info.LatencyMS = roundFloat(float64(observation.Latency.Microseconds())/1000.0, 2)
		}
		info.OSGuess, info.OSConfidence = inferOSFromNetworkSignals(observation.TTL)
	} else if errors.Is(observation.Err, context.Canceled) || errors.Is(observation.Err, context.DeadlineExceeded) {
		info.Status = "timeout"
	}

	if opts.EnableRDNS {
		info.Hostname = reverseLookupWithRetry(ctx, normalizedIP, opts.Retries+1)
		info.ReverseDNS = info.Hostname
	}

	enrichGeoDataWithContext(ctx, &info, opts)
	info.RiskTags = classifyIPRiskTags(info)
	if opts.EnableScripts {
		info.Scripts = runIPScripts(info)
	}

	if opts.CacheResults {
		hostCache.Lock()
		hostCache.values[normalizedIP] = info
		hostCache.Unlock()
	}

	return info
}

func discoverHost(ctx context.Context, ip string, opts IPScannerOptions) hostObservation {
	var best hostObservation
	for _, method := range opts.DiscoveryMethods {
		for attempt := 0; attempt <= opts.Retries; attempt++ {
			if opts.Delay > 0 {
				if err := sleepContext(ctx, opts.Delay); err != nil {
					return hostObservation{Err: err}
				}
			}

			observation := probeHost(ctx, ip, method, opts)
			if observation.Online {
				return observation
			}
			if best.Err == nil && observation.Err != nil {
				best = observation
			}
			if observation.Latency > 0 && (best.Latency == 0 || observation.Latency < best.Latency) {
				best = observation
			}
			sleepBackoff(ctx, opts.RetryBackoff, attempt)
		}
	}
	return best
}

func probeHost(ctx context.Context, ip, method string, opts IPScannerOptions) hostObservation {
	method = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(method), "-"))
	switch method {
	case "icmp", "pe", "echo":
		return icmpProbe(ctx, ip, 8, opts.Timeout)
	case "timestamp", "pp":
		return icmpProbe(ctx, ip, 13, opts.Timeout)
	case "netmask", "pm":
		return icmpProbe(ctx, ip, 17, opts.Timeout)
	case "tcp", "syn", "ps", "ack", "pa":
		return tcpConnectDiscovery(ctx, ip, opts)
	case "udp", "pu":
		return udpDiscovery(ctx, ip, opts)
	case "arp":
		if classifyIPType(ip) == "private" {
			return tcpConnectDiscovery(ctx, ip, opts)
		}
		return hostObservation{Method: "arp", Err: fmt.Errorf("arp discovery is limited to local private targets in this build")}
	case "sctp", "py":
		return hostObservation{Method: "sctp", Err: fmt.Errorf("sctp discovery is not available without platform-specific raw packet support")}
	default:
		return hostObservation{Method: method, Err: fmt.Errorf("unknown discovery method")}
	}
}

func icmpProbe(ctx context.Context, target string, icmpType byte, timeout time.Duration) hostObservation {
	start := time.Now()
	ip := net.ParseIP(target)
	if ip == nil || ip.To4() == nil {
		return hostObservation{Method: icmpMethodName(icmpType), Err: fmt.Errorf("raw ICMP probe supports IPv4 targets only")}
	}

	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return hostObservation{Method: icmpMethodName(icmpType), Err: err}
	}
	defer conn.Close()

	identifier := uint16(os.Getpid()+rand.Intn(65535)) & 0xffff
	sequence := uint16(rand.Intn(65535))
	packet := buildICMPPacket(icmpType, identifier, sequence)

	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)
	if _, err := conn.WriteTo(packet, &net.IPAddr{IP: ip}); err != nil {
		return hostObservation{Method: icmpMethodName(icmpType), Err: err}
	}

	buffer := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return hostObservation{Method: icmpMethodName(icmpType), Err: ctx.Err()}
		default:
		}

		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			return hostObservation{Method: icmpMethodName(icmpType), Err: err}
		}
		if addr == nil || !strings.EqualFold(addr.String(), ip.String()) {
			continue
		}

		payload := buffer[:n]
		ttl := 0
		if len(payload) >= 20 && payload[0]>>4 == 4 {
			ttl = int(payload[8])
			headerLen := int(payload[0]&0x0f) * 4
			if headerLen > 0 && headerLen < len(payload) {
				payload = payload[headerLen:]
			}
		}
		if len(payload) < 8 {
			continue
		}

		replyType := payload[0]
		if icmpReplyMatches(icmpType, replyType, payload, identifier) {
			return hostObservation{
				Online:  true,
				Method:  icmpMethodName(icmpType),
				TTL:     ttl,
				Latency: time.Since(start),
			}
		}
	}
}

func buildICMPPacket(icmpType byte, identifier, sequence uint16) []byte {
	length := 16
	if icmpType == 13 {
		length = 20
	}
	if icmpType == 17 {
		length = 12
	}

	packet := make([]byte, length)
	packet[0] = icmpType
	packet[1] = 0
	binary.BigEndian.PutUint16(packet[4:6], identifier)
	binary.BigEndian.PutUint16(packet[6:8], sequence)

	switch icmpType {
	case 8:
		copy(packet[8:], []byte("ECLIPSE!"))
	case 13:
		now := uint32(time.Now().UnixMilli() % int64(24*time.Hour/time.Millisecond))
		binary.BigEndian.PutUint32(packet[8:12], now)
	case 17:
		binary.BigEndian.PutUint32(packet[8:12], 0)
	}

	sum := checksum(packet)
	binary.BigEndian.PutUint16(packet[2:4], sum)
	return packet
}

func icmpReplyMatches(requestType, replyType byte, payload []byte, identifier uint16) bool {
	if replyType == 3 || replyType == 11 {
		return true
	}
	if len(payload) >= 6 {
		replyID := binary.BigEndian.Uint16(payload[4:6])
		if replyID != identifier {
			return false
		}
	}
	switch requestType {
	case 8:
		return replyType == 0
	case 13:
		return replyType == 14
	case 17:
		return replyType == 18
	default:
		return false
	}
}

func icmpMethodName(icmpType byte) string {
	switch icmpType {
	case 8:
		return "icmp-echo"
	case 13:
		return "icmp-timestamp"
	case 17:
		return "icmp-netmask"
	default:
		return "icmp"
	}
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) > 1 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpConnectDiscovery(ctx context.Context, ip string, opts IPScannerOptions) hostObservation {
	start := time.Now()
	dialer := net.Dialer{Timeout: opts.Timeout}
	if opts.SourcePort > 0 {
		dialer.LocalAddr = &net.TCPAddr{Port: opts.SourcePort}
	}

	var lastErr error
	for _, port := range opts.TCPPorts {
		select {
		case <-ctx.Done():
			return hostObservation{Method: "tcp-connect", Err: ctx.Err()}
		default:
		}
		address := net.JoinHostPort(ip, strconv.Itoa(port))
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			_ = conn.Close()
			return hostObservation{Online: true, Method: fmt.Sprintf("tcp-connect/%d", port), Latency: time.Since(start)}
		}
		lastErr = err
	}
	return hostObservation{Method: "tcp-connect", Err: lastErr}
}

func udpDiscovery(ctx context.Context, ip string, opts IPScannerOptions) hostObservation {
	start := time.Now()
	var lastErr error
	for _, port := range opts.UDPPorts {
		select {
		case <-ctx.Done():
			return hostObservation{Method: "udp", Err: ctx.Err()}
		default:
		}

		conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, strconv.Itoa(port)), opts.Timeout)
		if err != nil {
			lastErr = err
			continue
		}

		_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
		_, _ = conn.Write(udpDiscoveryPayload(port))
		buffer := make([]byte, 512)
		n, err := conn.Read(buffer)
		_ = conn.Close()
		if err == nil && n > 0 {
			return hostObservation{Online: true, Method: fmt.Sprintf("udp/%d", port), Latency: time.Since(start)}
		}
		lastErr = err
	}
	return hostObservation{Method: "udp", Err: lastErr}
}

func udpDiscoveryPayload(port int) []byte {
	if port == 53 {
		return []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01}
	}
	if port == 123 {
		packet := make([]byte, 48)
		packet[0] = 0x1b
		return packet
	}
	return []byte{0}
}

func reverseLookupWithRetry(ctx context.Context, ip string, attempts int) string {
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		resolver := net.Resolver{}
		names, err := resolver.LookupAddr(ctx, ip)
		if err == nil && len(names) > 0 {
			return strings.TrimSuffix(names[0], ".")
		}
		lastErr = err
		sleepBackoff(ctx, 100*time.Millisecond, i)
	}
	if lastErr != nil {
		ipLogger.Debug("reverse DNS lookup failed", "ip", ip, "error", lastErr)
	}
	return "N/A"
}

func inferOSFromNetworkSignals(ttl int) (string, string) {
	if ttl <= 0 {
		return "unknown", "low"
	}
	switch {
	case ttl <= 64:
		return "Linux/Unix-like", "medium"
	case ttl <= 128:
		return "Windows-family", "medium"
	default:
		return "network-appliance-or-BSD-family", "low"
	}
}

func classifyIPRiskTags(info IPInfo) []string {
	var tags []string
	if info.IPType == "public" {
		tags = append(tags, "publicly-routable")
	}
	if strings.EqualFold(info.Hosting, "yes") {
		tags = append(tags, "hosting-provider")
	}
	if strings.EqualFold(info.Proxy, "yes") {
		tags = append(tags, "proxy-detected")
	}
	if strings.EqualFold(info.ReverseDNS, "N/A") || strings.TrimSpace(info.ReverseDNS) == "" {
		tags = append(tags, "no-reverse-dns")
	}
	if strings.EqualFold(info.Status, "online") && info.IPType == "private" {
		tags = append(tags, "local-network-host")
	}
	return dedupeStrings(tags)
}

func runIPScripts(info IPInfo) []IPScriptResult {
	scripts := []IPScriptResult{
		{
			Name:     "host-summary",
			Status:   "ok",
			Output:   fmt.Sprintf("status=%s type=%s family=%s method=%s", info.Status, info.IPType, info.AddressFamily, defaultIfEmpty(info.DiscoveryMethod, "none")),
			Severity: "info",
		},
	}

	if info.IPType == "public" && (strings.EqualFold(info.Proxy, "yes") || strings.EqualFold(info.Hosting, "yes")) {
		scripts = append(scripts, IPScriptResult{
			Name:     "exposure-context",
			Status:   "review",
			Output:   "public hosting or proxy indicators were observed; validate ownership and perimeter policy",
			Severity: "medium",
		})
	}

	if info.OSGuess != "" && info.OSGuess != "unknown" {
		scripts = append(scripts, IPScriptResult{
			Name:     "os-ttl-fingerprint",
			Status:   "ok",
			Output:   fmt.Sprintf("%s confidence=%s ttl=%d", info.OSGuess, info.OSConfidence, info.TTL),
			Severity: "info",
		})
	}

	return scripts
}

func boolToLabel(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func buildScanResults(mode string, allResults []IPInfo) ScanResults {
	return buildScanResultsWithOptions(mode, allResults, defaultIPScannerOptions())
}

func buildScanResultsWithOptions(mode string, allResults []IPInfo, opts IPScannerOptions) ScanResults {
	online := 0
	offline := 0
	timedOut := 0
	for _, info := range allResults {
		switch info.Status {
		case "online":
			online++
		case "timeout":
			timedOut++
			offline++
		default:
			offline++
		}
	}

	return ScanResults{
		ScanMode:         mode,
		DiscoveryMethods: opts.DiscoveryMethods,
		TotalScanned:     len(allResults),
		Online:           online,
		Offline:          offline,
		TimedOut:         timedOut,
		OutputFormat:     opts.OutputFormat,
		Concurrency:      opts.Concurrency,
		TimeoutMS:        opts.Timeout.Milliseconds(),
		RateLimit:        opts.RateLimit,
		TimingTemplate:   opts.TimingTemplate,
		SafetyNotes:      opts.SafetyNotes,
		ScannedAt:        time.Now(),
		IPs:              allResults,
	}
}

func IpScanner() {
	utils.ClearTerminal()
	fmt.Printf("\n%s=== IP SCANNER ===%s\n\n", utils.Blue, utils.Reset)

	reader := bufio.NewReader(os.Stdin)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Printf("%sChoose scan mode:%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s[1] Range (e.g., 192.168.1.1-255)%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[2] Single IP%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[3] My public IP%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[4] Complete Mode (safe full discovery + enrichment)%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[5] Flags quick help%s\n", utils.Green, utils.Reset)
	fmt.Printf("\n%sTip: choose Flags quick help or type help in Advanced options.%s\n", utils.Yellow, utils.Reset)
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
		fmt.Printf("%sEnter full IP (IPv4 or IPv6): %s", utils.Green, utils.Reset)
		inputIP, _ := reader.ReadString('\n')
		inputIP = strings.TrimSpace(inputIP)

		if !isValidIP(inputIP) {
			fmt.Printf("\n%sInvalid IP address.%s\n", utils.Red, utils.Reset)
			utils.WaitForEnter(reader)
			return
		}

		targets = []string{inputIP}
	case "3":
		mode = "my-public-ip"
		publicIP, publicErr := getPublicIPv4WithContext(ctx)
		if publicErr != nil {
			fmt.Printf("\n%sCould not detect your public IP: %v%s\n", utils.Red, publicErr, utils.Reset)
			utils.WaitForEnter(reader)
			return
		}

		fmt.Printf("\n%sDetected public IP: %s%s\n", utils.Yellow, publicIP, utils.Reset)
		targets = []string{publicIP}
	case "4":
		mode = "complete"
		var ok bool
		targets, ok = promptCompleteIPTargets(reader)
		if !ok {
			utils.WaitForEnter(reader)
			return
		}
	case "5":
		printIPScannerFlagHelp()
		utils.WaitForEnter(reader)
		return
	default:
		fmt.Printf("\n%sInvalid option!%s\n", utils.Red, utils.Reset)
		utils.WaitForEnter(reader)
		return
	}

	var opts IPScannerOptions
	if mode == "complete" {
		opts = completeIPScannerOptions()
	} else {
		opts = promptIPScannerOptions(reader)
	}
	fmt.Printf("\n%sScanning %d target(s) with T%d, concurrency=%d, timeout=%s...%s\n\n",
		utils.Yellow, len(targets), opts.TimingTemplate, opts.Concurrency, opts.Timeout, utils.Reset)

	startTime := time.Now()
	scanResults := runIPScan(ctx, mode, targets, opts, true)
	duration := time.Since(startTime)

	saveResults(scanResults)

	utils.ClearTerminal()
	displayResults(scanResults, duration)
	utils.WaitForEnter(reader)
}

func promptIPScannerOptions(reader *bufio.Reader) IPScannerOptions {
	fmt.Printf("\n%sAdvanced options (Enter = defaults). Examples:%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s  -T4 --concurrency 256 --timeout 800ms --rate 500 --discovery icmp,tcp --output-format json%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("%s  Type help to show all common flags. Complete Mode ignores manual flags and uses the safe best profile.%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("%sOptions: %s", utils.Green, utils.Reset)

	raw, _ := reader.ReadString('\n')
	if strings.EqualFold(strings.TrimSpace(raw), "help") {
		printIPScannerFlagHelp()
		return promptIPScannerOptions(reader)
	}
	return parseIPScannerOptions(raw)
}

func promptCompleteIPTargets(reader *bufio.Reader) ([]string, bool) {
	fmt.Printf("%sTarget expression (IP, CIDR, or range like 192.168.1.1-20): %s", utils.Green, utils.Reset)
	raw, _ := reader.ReadString('\n')
	targets, err := parseIPTargetExpression(raw, 4096)
	if err != nil {
		fmt.Printf("%sInvalid target expression: %v%s\n", utils.Red, err, utils.Reset)
		return nil, false
	}
	fmt.Printf("%sComplete Mode selected %d target(s).%s\n", utils.Yellow, len(targets), utils.Reset)
	return targets, true
}

func completeIPScannerOptions() IPScannerOptions {
	opts := defaultIPScannerOptions()
	opts.TimingTemplate = 4
	applyIPTimingTemplate(&opts)
	opts.DiscoveryMethods = []string{"icmp", "timestamp", "netmask", "tcp", "udp"}
	opts.TCPPorts = []int{22, 25, 53, 80, 110, 139, 143, 443, 445, 587, 993, 995, 3389, 8080, 8443}
	opts.UDPPorts = []int{53, 123, 161}
	opts.OutputFormat = "all"
	opts.EnableGeo = true
	opts.EnableRDNS = true
	opts.EnableScripts = true
	opts.CacheResults = true
	opts.SafetyNotes = append(opts.SafetyNotes, "Complete Mode uses all safe discovery probes, reverse DNS, enrichment, scripts, and OS heuristics.")
	return opts
}

func printIPScannerFlagHelp() {
	fmt.Printf("\n%sIP Scanner flags:%s\n", utils.Blue, utils.Reset)
	fmt.Printf("  -T0..-T5              Timing profile, from slow/careful to fast/aggressive.\n")
	fmt.Printf("  --concurrency 256     Number of parallel hosts scanned.\n")
	fmt.Printf("  --timeout 800ms       Per-probe timeout.\n")
	fmt.Printf("  --rate 500/s          Maximum probes per second.\n")
	fmt.Printf("  --discovery icmp,tcp  Host discovery methods: icmp,tcp,udp,timestamp,netmask,arp,sctp.\n")
	fmt.Printf("  --tcp-probes 22,80    TCP ports used for host discovery fallback.\n")
	fmt.Printf("  --udp-probes 53,123   UDP ports used for host discovery fallback.\n")
	fmt.Printf("  --output-format xml   Extra output: json, xml, grep, or all.\n")
	fmt.Printf("  --no-geo              Skip public IP geolocation enrichment.\n")
	fmt.Printf("  --no-rdns             Skip reverse DNS lookups.\n")
	fmt.Printf("  --no-scripts          Skip passive built-in scripts.\n")
	fmt.Printf("  --log-level debug     Log level: debug, info, warn, error.\n")
	fmt.Printf("\n%sExample:%s -T4 --concurrency 256 --timeout 800ms --rate 800/s --discovery icmp,tcp,udp --output-format xml\n\n", utils.Yellow, utils.Reset)
}

func parseIPTargetExpression(raw string, maxTargets int) ([]string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}
	if strings.Contains(value, "/") {
		return expandCIDRTargets(value, maxTargets)
	}
	if strings.Contains(value, "-") {
		return expandInlineIPRange(value, maxTargets)
	}
	if !isValidIP(value) {
		return nil, fmt.Errorf("invalid IP address")
	}
	return []string{value}, nil
}

func expandInlineIPRange(value string, maxTargets int) ([]string, error) {
	left, right, ok := strings.Cut(strings.TrimSpace(value), "-")
	if !ok {
		return nil, fmt.Errorf("range must use start-end")
	}
	startIP := net.ParseIP(strings.TrimSpace(left)).To4()
	if startIP == nil {
		return nil, fmt.Errorf("range start must be IPv4")
	}

	baseParts := strings.Split(strings.TrimSpace(left), ".")
	if len(baseParts) != 4 {
		return nil, fmt.Errorf("range start must be IPv4")
	}

	endValue := strings.TrimSpace(right)
	endIP := net.ParseIP(endValue).To4()
	if endIP == nil {
		octet, err := strconv.Atoi(endValue)
		if err != nil || octet < 0 || octet > 255 {
			return nil, fmt.Errorf("range end must be IPv4 or last octet")
		}
		endIP = net.ParseIP(fmt.Sprintf("%s.%s.%s.%d", baseParts[0], baseParts[1], baseParts[2], octet)).To4()
	}

	start := binary.BigEndian.Uint32(startIP)
	end := binary.BigEndian.Uint32(endIP)
	if start > end {
		start, end = end, start
	}
	if int(end-start+1) > maxTargets {
		return nil, fmt.Errorf("range too large, max %d targets", maxTargets)
	}

	targets := make([]string, 0, int(end-start+1))
	for current := start; current <= end; current++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, current)
		targets = append(targets, ip.String())
		if current == ^uint32(0) {
			break
		}
	}
	return targets, nil
}

func expandCIDRTargets(value string, maxTargets int) ([]string, error) {
	ip, network, err := net.ParseCIDR(strings.TrimSpace(value))
	if err != nil {
		return nil, err
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("CIDR expansion supports IPv4 only")
	}

	var targets []string
	for current := ip4.Mask(network.Mask); network.Contains(current); incrementIPv4(current) {
		copied := make(net.IP, len(current))
		copy(copied, current)
		targets = append(targets, copied.String())
		if len(targets) > maxTargets {
			return nil, fmt.Errorf("CIDR too large, max %d targets", maxTargets)
		}
	}
	if len(targets) > 2 {
		targets = targets[1 : len(targets)-1]
	}
	return targets, nil
}

func incrementIPv4(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

func runIPScan(ctx context.Context, mode string, targets []string, opts IPScannerOptions, showProgress bool) ScanResults {
	total := len(targets)
	if total == 0 {
		return buildScanResultsWithOptions(mode, []IPInfo{}, opts)
	}

	limiter := newSimpleRateLimiter(opts.RateLimit)
	defer limiter.Stop()

	results := make(chan IPInfo, total)
	semaphore := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	var completed int64
	startTime := time.Now()

	var doneProgress chan struct{}
	if showProgress {
		doneProgress = make(chan struct{})
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-doneProgress:
					return
				case <-ticker.C:
					done := int(atomic.LoadInt64(&completed))
					elapsed := time.Since(startTime).Seconds()
					rate := 0.0
					if elapsed > 0 {
						rate = float64(done) / elapsed
					}
					remaining := 0.0
					if rate > 0 {
						remaining = float64(total-done) / rate
					}
					fmt.Printf("%s[Progress] %d/%d (%.1f%%) | rate %.1f hosts/s | ETA %.0fs%s\n",
						utils.Blue, done, total, percent(done, total), rate, math.Max(0, remaining), utils.Reset)
				}
			}
		}()
	}

	for i, targetIP := range targets {
		wg.Add(1)
		go func(ip string, idx int) {
			defer wg.Done()

			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				results <- cancelledIPInfo(ip)
				atomic.AddInt64(&completed, 1)
				return
			}

			if err := limiter.Wait(ctx); err != nil {
				results <- cancelledIPInfo(ip)
				atomic.AddInt64(&completed, 1)
				return
			}

			if showProgress && total <= 256 {
				fmt.Printf("%s[%d/%d] Scanning %s...%s\n", utils.Yellow, idx+1, total, ip, utils.Reset)
			}
			info := scanSingleIPWithOptions(ctx, ip, opts)
			results <- info
			atomic.AddInt64(&completed, 1)
		}(targetIP, i)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	allResults := make([]IPInfo, 0, total)
	for info := range results {
		allResults = append(allResults, info)
	}

	if doneProgress != nil {
		close(doneProgress)
	}

	sort.Slice(allResults, func(i, j int) bool {
		return compareIPStrings(allResults[i].IP, allResults[j].IP)
	})

	return buildScanResultsWithOptions(mode, allResults, opts)
}

func cancelledIPInfo(ip string) IPInfo {
	return IPInfo{
		IP:            strings.TrimSpace(ip),
		Status:        "timeout",
		IPType:        classifyIPType(ip),
		AddressFamily: addressFamily(ip),
		ScannedBy:     "user",
		LastScanned:   time.Now(),
	}
}

func compareIPStrings(a, b string) bool {
	ipa := net.ParseIP(a)
	ipb := net.ParseIP(b)
	if ipa == nil || ipb == nil {
		return a < b
	}
	ba := ipa.To16()
	bb := ipb.To16()
	if ba == nil || bb == nil {
		return a < b
	}
	return strings.Compare(string(ba), string(bb)) < 0
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

	if err := os.WriteFile(resultsFile, data, 0644); err != nil {
		fmt.Printf("%sError writing file: %v%s\n", utils.Red, err, utils.Reset)
		return
	}

	if err := writeIPOutputFormat(results); err != nil {
		fmt.Printf("%sError writing %s output: %v%s\n", utils.Red, results.OutputFormat, err, utils.Reset)
		return
	}

	fmt.Printf("%s\nResults saved to %s%s\n", utils.Green, resultsFile, utils.Reset)
}

func writeIPOutputFormat(results ScanResults) error {
	switch strings.ToLower(strings.TrimSpace(results.OutputFormat)) {
	case "", "json":
		return nil
	case "xml":
		data, err := xml.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		data = append([]byte(xml.Header), data...)
		return os.WriteFile(ipXMLFile, data, 0644)
	case "grep":
		var builder strings.Builder
		for _, info := range results.IPs {
			fmt.Fprintf(&builder, "Host: %s (%s) Status: %s Type: %s Method: %s OS: %s LatencyMS: %.2f\n",
				info.IP, defaultValue(info.Hostname), info.Status, info.IPType, defaultValue(info.DiscoveryMethod), defaultValue(info.OSGuess), info.LatencyMS)
		}
		return os.WriteFile(ipGrepFile, []byte(builder.String()), 0644)
	case "all":
		xmlData, err := xml.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		xmlData = append([]byte(xml.Header), xmlData...)
		if err := os.WriteFile(ipXMLFile, xmlData, 0644); err != nil {
			return err
		}
		var builder strings.Builder
		for _, info := range results.IPs {
			fmt.Fprintf(&builder, "Host: %s (%s) Status: %s Type: %s Method: %s OS: %s LatencyMS: %.2f\n",
				info.IP, defaultValue(info.Hostname), info.Status, info.IPType, defaultValue(info.DiscoveryMethod), defaultValue(info.OSGuess), info.LatencyMS)
		}
		return os.WriteFile(ipGrepFile, []byte(builder.String()), 0644)
	default:
		return nil
	}
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
		fmt.Printf("%s[%d] %s | mode=%s | total=%d | online=%d | offline=%d | T%d%s\n",
			utils.Yellow, i+1, scan.ScannedAt.Format("2006-01-02 15:04:05"),
			scan.ScanMode, scan.TotalScanned, scan.Online, scan.Offline, scan.TimingTemplate, utils.Reset)
	}
}

func displayResults(results ScanResults, duration time.Duration) {
	fmt.Printf("\n%s=========================== SCAN STATISTICS ===========================%s\n", utils.Blue, utils.Reset)

	publicCount, privateCount := countByIPType(results.IPs)
	topCountries := topFromField(results.IPs, func(i IPInfo) string { return i.Country }, 3)
	topISPs := topFromField(results.IPs, func(i IPInfo) string { return i.ISP }, 3)

	fmt.Printf("\n%s  Mode:              %s%s%s\n", utils.Green, utils.Yellow, results.ScanMode, utils.Reset)
	fmt.Printf("%s  Discovery:         %s%s%s\n", utils.Green, utils.Yellow, strings.Join(results.DiscoveryMethods, ","), utils.Reset)
	fmt.Printf("%s  Total Scanned:     %s%d%s\n", utils.Green, utils.Yellow, results.TotalScanned, utils.Reset)
	fmt.Printf("%s  Online:            %s%d%s\n", utils.Green, utils.Green, results.Online, utils.Reset)
	fmt.Printf("%s  Offline:           %s%d%s\n", utils.Green, utils.Red, results.Offline, utils.Reset)
	fmt.Printf("%s  Public IPs:        %s%d%s\n", utils.Green, utils.Yellow, publicCount, utils.Reset)
	fmt.Printf("%s  Private IPs:       %s%d%s\n", utils.Green, utils.Yellow, privateCount, utils.Reset)
	fmt.Printf("%s  Timing:            %sT%d | concurrency=%d | timeout=%dms | rate=%d/s%s\n",
		utils.Green, utils.Yellow, results.TimingTemplate, results.Concurrency, results.TimeoutMS, results.RateLimit, utils.Reset)
	if duration > 0 {
		fmt.Printf("%s  Scan Duration:     %s%.2fs%s\n", utils.Green, utils.Yellow, duration.Seconds(), utils.Reset)
	}
	fmt.Printf("%s  Scanned At:        %s%s%s\n", utils.Green, utils.Yellow, results.ScannedAt.Format("2006-01-02 15:04:05"), utils.Reset)
	fmt.Printf("%s  Output Format:     %s%s%s\n", utils.Green, utils.Yellow, defaultValue(results.OutputFormat), utils.Reset)
	fmt.Printf("%s  Top Countries:     %s%s%s\n", utils.Green, utils.Yellow, strings.Join(topCountries, ", "), utils.Reset)
	fmt.Printf("%s  Top ISPs:          %s%s%s\n\n", utils.Green, utils.Yellow, strings.Join(topISPs, ", "), utils.Reset)

	if len(results.SafetyNotes) > 0 {
		fmt.Printf("%sSafety notes:%s\n", utils.Yellow, utils.Reset)
		for _, note := range results.SafetyNotes {
			fmt.Printf("  - %s\n", note)
		}
		fmt.Println()
	}

	fmt.Printf("%s=========================== SCANNED IP DETAILS =========================%s\n\n", utils.Blue, utils.Reset)

	for i, info := range results.IPs {
		statusColor := utils.Red
		if info.Status == "online" {
			statusColor = utils.Green
		}

		fmt.Printf("%s[%d] IP: %s%s%s | Status: %s%s%s | Type: %s%s%s | Family: %s\n",
			utils.Yellow, i+1, utils.Blue, info.IP, utils.Reset, statusColor, info.Status, utils.Reset, utils.Purple, info.IPType, utils.Reset, info.AddressFamily)
		fmt.Printf("    Scanned at:      %s - %s\n", info.LastScanned.Format("2006-01-02 15:04:05"), defaultValue(info.ScannedBy))
		fmt.Printf("    Discovery:       %s | latency %.2f ms | TTL %d\n", defaultValue(info.DiscoveryMethod), info.LatencyMS, info.TTL)
		fmt.Printf("    OS Guess:        %s (%s confidence)\n", defaultValue(info.OSGuess), defaultValue(info.OSConfidence))
		fmt.Printf("    Hostname:        %s\n", defaultValue(info.Hostname))
		fmt.Printf("    Reverse DNS:     %s\n", defaultValue(info.ReverseDNS))
		fmt.Printf("    ASN/AS Name:     %s | %s\n", defaultValue(info.ASN), defaultValue(info.ASName))
		fmt.Printf("    ISP:             %s\n", defaultValue(info.ISP))
		fmt.Printf("    Organization:    %s\n", defaultValue(info.Organization))
		fmt.Printf("    Continent:       %s\n", defaultValue(info.Continent))
		fmt.Printf("    Country:         %s (%s)\n", defaultValue(info.Country), defaultValue(info.CountryCode))
		fmt.Printf("    Region:          %s (%s)\n", defaultValue(info.Region), defaultValue(info.RegionCode))
		fmt.Printf("    City/District:   %s / %s\n", defaultValue(info.City), defaultValue(info.District))
		fmt.Printf("    ZIP:             %s\n", defaultValue(info.ZIP))
		fmt.Printf("    Coordinates:     %s, %s\n", defaultValue(info.Latitude), defaultValue(info.Longitude))
		fmt.Printf("    Timezone:        %s (%s)\n", defaultValue(info.Timezone), defaultValue(info.TimezoneOffset))
		fmt.Printf("    Currency:        %s %s\n", defaultValue(info.Currency), defaultValue(info.CurrencySymbol))
		fmt.Printf("    Mobile/Carrier:  %s / %s\n", defaultValue(info.Mobile), defaultValue(info.MobileCarrier))
		fmt.Printf("    Proxy/Type:      %s / %s\n", defaultValue(info.Proxy), defaultValue(info.ProxyType))
		fmt.Printf("    Hosting:         %s\n", defaultValue(info.Hosting))
		if len(info.RiskTags) > 0 {
			fmt.Printf("    Risk Tags:       %s\n", strings.Join(info.RiskTags, ", "))
		}
		if len(info.Scripts) > 0 {
			fmt.Printf("    Scripts:\n")
			for _, script := range info.Scripts {
				fmt.Printf("      - %s [%s]: %s\n", script.Name, script.Status, script.Output)
			}
		}
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
		case "private", "loopback", "link-local":
			privateCount++
		}
	}
	return publicCount, privateCount
}

func topFromField(ips []IPInfo, field func(IPInfo) string, n int) []string {
	counts := map[string]int{}
	for _, ip := range ips {
		value := strings.TrimSpace(field(ip))
		if value == "" || value == "N/A" || value == "Private or non-public network" {
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

func defaultIfEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
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
	utils.PrintReturnOption("3")
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	opts := defaultIPScannerOptions()
	if oldResults.Concurrency > 0 {
		opts.Concurrency = oldResults.Concurrency
	}
	if oldResults.TimeoutMS > 0 {
		opts.Timeout = time.Duration(oldResults.TimeoutMS) * time.Millisecond
	}
	if oldResults.RateLimit > 0 {
		opts.RateLimit = oldResults.RateLimit
	}
	if oldResults.TimingTemplate >= 0 && oldResults.TimingTemplate <= 5 {
		opts.TimingTemplate = oldResults.TimingTemplate
	}
	if len(oldResults.DiscoveryMethods) > 0 {
		opts.DiscoveryMethods = oldResults.DiscoveryMethods
	}
	if oldResults.OutputFormat != "" {
		opts.OutputFormat = oldResults.OutputFormat
	}

	targets := make([]string, 0, len(oldResults.IPs))
	for _, oldInfo := range oldResults.IPs {
		targets = append(targets, oldInfo.IP)
	}

	startTime := time.Now()
	scanResults := runIPScan(ctx, "refresh:"+oldResults.ScanMode, targets, opts, true)
	duration := time.Since(startTime)

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
		_ = os.Remove(ipXMLFile)
		_ = os.Remove(ipGrepFile)
		fmt.Printf("%sResults deleted successfully!%s\n", utils.Green, utils.Reset)
	}
	time.Sleep(2 * time.Second)
}

func sleepBackoff(ctx context.Context, base time.Duration, attempt int) {
	if base <= 0 || attempt < 0 {
		return
	}
	delay := base * time.Duration(1<<minInt(attempt, 6))
	_ = sleepContext(ctx, delay)
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func percent(done, total int) float64 {
	if total <= 0 {
		return 100
	}
	return (float64(done) / float64(total)) * 100.0
}

func roundFloat(value float64, places int) float64 {
	pow := math.Pow(10, float64(places))
	return math.Round(value*pow) / pow
}

func clamp(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
