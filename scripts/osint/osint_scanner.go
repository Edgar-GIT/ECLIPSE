package osint

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"programa/utils"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type OSINTRecord struct {
	Tool            string    `json:"tool"`
	Target          string    `json:"target"`
	Status          string    `json:"status"`
	Summary         string    `json:"summary"`
	OutputFile      string    `json:"output_file,omitempty"`
	DurationSeconds float64   `json:"duration_seconds"`
	RanAt           time.Time `json:"ran_at"`
}

type OSINTHistory struct {
	Records []OSINTRecord `json:"records"`
}

type OSINTStats struct {
	TotalRuns       int
	SuccessRuns     int
	WarningRuns     int
	ErrorRuns       int
	UniqueTools     int
	UniqueTargets   int
	LastRun         time.Time
	AverageDuration float64
	TopTools        []string
	TopTargets      []string
}

var (
	workspaceRootOnce sync.Once
	workspaceRootVal  string
)

func workspaceRoot() string {
	workspaceRootOnce.Do(initWorkspaceRoot)
	return workspaceRootVal
}

func initWorkspaceRoot() {
	if v := strings.TrimSpace(os.Getenv("ECLIPSE_ROOT")); v != "" {
		workspaceRootVal = filepath.Clean(v)
		return
	}
	seen := map[string]struct{}{}
	tryRoots := func(start string) bool {
		start = filepath.Clean(start)
		if start == "" || start == "." {
			return false
		}
		if _, dup := seen[start]; dup {
			return false
		}
		seen[start] = struct{}{}
		for dir := start; dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
			st, err := os.Stat(filepath.Join(dir, "go.mod"))
			if err == nil && !st.IsDir() {
				workspaceRootVal = dir
				return true
			}
		}
		return false
	}
	if wd, err := os.Getwd(); err == nil && tryRoots(wd) {
		return
	}
	if exe, err := os.Executable(); err == nil {
		if tryRoots(filepath.Dir(exe)) {
			return
		}
	}
	if wd, err := os.Getwd(); err == nil {
		workspaceRootVal = wd
		return
	}
	workspaceRootVal = "."
}

func pathOSINTResults() string {
	return filepath.Join(workspaceRoot(), "target", "osint_results.json")
}

func pathOSINTReports() string {
	return filepath.Join(workspaceRoot(), "target", "osint_reports")
}

func maigretOutputDir() string {
	d := filepath.Join(pathOSINTReports(), "maigret")
	_ = os.MkdirAll(d, 0755)
	return d
}

func pathOSINTAPIKeys() string {
	return filepath.Join(workspaceRoot(), "target", "osint_api_keys.json")
}

func pathExecTools() string {
	return filepath.Join(workspaceRoot(), "exec_tools")
}

func pathLegacyOSINTTools() string {
	return filepath.Join(workspaceRoot(), "target", "osint_tools")
}

var apiKeyHelpLinks = map[string]string{
	"SHODAN_API_KEY": "https://account.shodan.io/",
}

var (
	osintDomainHostRegexp = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$`)
	osintEmailRegexp      = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
)

func OSINTToolkit() {
	reader := bufio.NewReader(os.Stdin)
	loadStoredAPIKeysIntoEnv()
	ensureExecToolsDir()

	for {
		utils.ClearTerminal()
		printOSINTHeader("OSINT Toolkit")
		fmt.Printf("%s[1] Username / handle intelligence%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[2] IP address / infrastructure%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[3] Email address intelligence%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[4] Domain / website intelligence%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[5] Full OSINT frameworks%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[6] API key manager%s\n", utils.Blue, utils.Reset)
		fmt.Printf("%s[7] History and statistics%s\n", utils.Blue, utils.Reset)
		fmt.Printf("%s[8] Tool setup and status%s\n", utils.Blue, utils.Reset)
		fmt.Printf("%s[9] Return to main menu%s\n", utils.Yellow, utils.Reset)
		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)

		input, ok := readMenuInput(reader)
		if !ok {
			return
		}

		switch input {
		case "1":
			usernameOSINTMenu(reader)
		case "2":
			ipOSINTMenu(reader)
		case "3":
			emailOSINTMenu(reader)
		case "4":
			domainOSINTMenu(reader)
		case "5":
			frameworksOSINTMenu(reader)
		case "6":
			manageAPIKeys(reader)
			utils.WaitForEnter(reader)
		case "7":
			ViewOSINTStats()
			utils.WaitForEnter(reader)
		case "8":
			setupOSINTToolsMenu(reader)
		case "9":
			return
		default:
			fmt.Printf("%sInvalid option!%s\n\n", utils.Red, utils.Reset)
			utils.WaitForEnter(reader)
		}
	}
}

func printOSINTHeader(title string) {
	fmt.Printf("\n%s=== %s ===%s\n\n", utils.Blue, strings.ToUpper(title), utils.Reset)
	fmt.Printf("%sUse only on authorized targets and lawful investigations.%s\n\n", utils.Yellow, utils.Reset)
}

func usernameOSINTMenu(reader *bufio.Reader) {
	for {
		utils.ClearTerminal()
		printOSINTHeader("Username Intelligence")
		fmt.Printf("%s[1] Sherlock username check%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[2] Maigret profile lookup%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[3] Back%s\n", utils.Yellow, utils.Reset)
		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)
		input, ok := readMenuInput(reader)
		if !ok {
			return
		}

		switch input {
		case "1":
			if !ensurePythonPackageToolReady(reader, "sherlock", "sherlock-project") {
				utils.WaitForEnter(reader)
				continue
			}
			target := askTarget(reader, "Username")
			if target == "" {
				fmt.Printf("%sUsername is required.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				continue
			}
			runOSINTCommand("sherlock", target, "sherlock", []string{"--print-found", target})
			utils.WaitForEnter(reader)
		case "2":
			if !ensureLocalOrGlobalToolReady(reader, "maigret") {
				utils.WaitForEnter(reader)
				continue
			}
			target := askTarget(reader, "Username")
			if target == "" {
				fmt.Printf("%sUsername is required.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				continue
			}
			runMaigretLookup(target)
			utils.WaitForEnter(reader)
		case "3":
			return
		default:
			fmt.Printf("%sInvalid option.%s\n", utils.Red, utils.Reset)
			utils.WaitForEnter(reader)
		}
	}
}

func ipOSINTMenu(reader *bufio.Reader) {
	for {
		utils.ClearTerminal()
		printOSINTHeader("IP Intelligence")
		fmt.Printf("%s[1] Reverse DNS and web finder (hostname, IP, or URL)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[2] Shodan InternetDB (hostname, IP, or URL)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[3] Shodan host lookup / CLI (hostname, IP, or URL)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[4] Whois lookup%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[5] Back%s\n", utils.Yellow, utils.Reset)
		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)
		input, ok := readMenuInput(reader)
		if !ok {
			return
		}

		switch input {
		case "1":
			target := askTarget(reader, "Hostname, IP, or URL")
			ip, err := resolvedIPForOSINT(target)
			if err != nil {
				fmt.Printf("%s%s%s\n", utils.Red, err.Error(), utils.Reset)
				utils.WaitForEnter(reader)
				continue
			}
			runIPWebFinder(ip, target)
			utils.WaitForEnter(reader)
		case "2":
			target := askTarget(reader, "Hostname, IP, or URL")
			ip, err := resolvedIPForOSINT(target)
			if err != nil {
				fmt.Printf("%s%s%s\n", utils.Red, err.Error(), utils.Reset)
				utils.WaitForEnter(reader)
				continue
			}
			runShodanInternetDB(ip, target)
			utils.WaitForEnter(reader)
		case "3":
			if !ensureAPIKeysForOption(reader, "shodan-cli") || !ensurePythonPackageToolReady(reader, "shodan", "shodan") {
				utils.WaitForEnter(reader)
				continue
			}
			ensureShodanCLIConfigured()
			target := askTarget(reader, "Hostname, IP, or URL")
			ip, err := resolvedIPForOSINT(target)
			if err != nil {
				fmt.Printf("%s%s%s\n", utils.Red, err.Error(), utils.Reset)
				utils.WaitForEnter(reader)
				continue
			}
			runOSINTCommand("shodan-cli", target, "shodan", []string{"host", ip})
			utils.WaitForEnter(reader)
		case "4":
			if !ensureDependenciesForOSINTOption(reader, "whois") {
				utils.WaitForEnter(reader)
				continue
			}
			raw := askTarget(reader, "Domain, IP, or URL")
			if raw == "" {
				fmt.Printf("%sTarget is required.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				continue
			}
			q, err := normalizeOSINTHostInput(raw)
			if err != nil {
				fmt.Printf("%s%s%s\n", utils.Red, err.Error(), utils.Reset)
				utils.WaitForEnter(reader)
				continue
			}
			runOSINTCommand("whois", q, "whois", []string{q})
			utils.WaitForEnter(reader)
		case "5":
			return
		default:
			fmt.Printf("%sInvalid option.%s\n", utils.Red, utils.Reset)
			utils.WaitForEnter(reader)
		}
	}
}

func emailOSINTMenu(reader *bufio.Reader) {
	for {
		utils.ClearTerminal()
		printOSINTHeader("Email Intelligence")
		fmt.Printf("%s[1] Mail domain footprint (MX/SPF/DMARC/NS)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[2] Back%s\n", utils.Yellow, utils.Reset)
		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)
		input, ok := readMenuInput(reader)
		if !ok {
			return
		}

		switch input {
		case "1":
			target := askTarget(reader, "Email address")
			if !isLikelyEmail(target) {
				fmt.Printf("%sInvalid email format.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				continue
			}
			runEmailDomainFootprint(target)
			utils.WaitForEnter(reader)
		case "2":
			return
		default:
			fmt.Printf("%sInvalid option.%s\n", utils.Red, utils.Reset)
			utils.WaitForEnter(reader)
		}
	}
}

func domainOSINTMenu(reader *bufio.Reader) {
	for {
		utils.ClearTerminal()
		printOSINTHeader("Domain and Website Intelligence")
		fmt.Printf("%s[1] DNS records (A/AAAA/MX/TXT/NS; reverse if IP)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[2] Website finder and IP mapping (domain, IP, or URL)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[3] Passive subdomain enum (domain name)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[4] TheHarvester domain recon (domain name)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[5] Whois lookup (domain, IP, or URL)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[6] Back%s\n", utils.Yellow, utils.Reset)
		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)
		input, ok := readMenuInput(reader)
		if !ok {
			return
		}

		switch input {
		case "1":
			if !ensureDependenciesForOSINTOption(reader, "dns") {
				utils.WaitForEnter(reader)
				continue
			}
			target := askHostOrDomainTarget(reader)
			if target == "" {
				utils.WaitForEnter(reader)
				continue
			}
			runDNSRecon(target)
			utils.WaitForEnter(reader)
		case "2":
			target := askHostOrDomainTarget(reader)
			if target == "" {
				utils.WaitForEnter(reader)
				continue
			}
			if isIPAddressString(target) {
				runIPWebFinder(target, target)
			} else {
				runDomainWebFinder(target)
			}
			utils.WaitForEnter(reader)
		case "3":
			if !ensureSubdomainToolReady(reader) {
				utils.WaitForEnter(reader)
				continue
			}
			target := askDomainNameTarget(reader)
			if target == "" {
				utils.WaitForEnter(reader)
				continue
			}
			runSubdomainEnum(target)
			utils.WaitForEnter(reader)
		case "4":
			if !ensureLocalOrGlobalToolReady(reader, "theharvester") {
				utils.WaitForEnter(reader)
				continue
			}
			target := askDomainNameTarget(reader)
			if target == "" {
				utils.WaitForEnter(reader)
				continue
			}
			runTheHarvester(target)
			utils.WaitForEnter(reader)
		case "5":
			if !ensureDependenciesForOSINTOption(reader, "whois") {
				utils.WaitForEnter(reader)
				continue
			}
			target := askHostOrDomainTarget(reader)
			if target == "" {
				utils.WaitForEnter(reader)
				continue
			}
			runOSINTCommand("whois", target, "whois", []string{target})
			utils.WaitForEnter(reader)
		case "6":
			return
		default:
			fmt.Printf("%sInvalid option.%s\n", utils.Red, utils.Reset)
			utils.WaitForEnter(reader)
		}
	}
}

func frameworksOSINTMenu(reader *bufio.Reader) {
	for {
		utils.ClearTerminal()
		printOSINTHeader("Full OSINT Frameworks")
		fmt.Printf("%s[1] Recon-ng quick module run (domain name)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[2] SpiderFoot quick scan (domain, IP, or URL)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[3] Maigret username lookup%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[4] Back%s\n", utils.Yellow, utils.Reset)
		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)
		input, ok := readMenuInput(reader)
		if !ok {
			return
		}

		switch input {
		case "1":
			if !ensureLocalOrGlobalToolReady(reader, "recon-ng") {
				utils.WaitForEnter(reader)
				continue
			}
			target := askDomainNameTarget(reader)
			if target == "" {
				utils.WaitForEnter(reader)
				continue
			}
			runReconNG(target)
			utils.WaitForEnter(reader)
		case "2":
			if !ensureLocalOrGlobalToolReady(reader, "spiderfoot") {
				utils.WaitForEnter(reader)
				continue
			}
			raw := askTarget(reader, "Domain, IP, or URL")
			if raw == "" {
				fmt.Printf("%sTarget is required.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				continue
			}
			target, err := normalizeOSINTHostInput(raw)
			if err != nil {
				fmt.Printf("%s%s%s\n", utils.Red, err.Error(), utils.Reset)
				utils.WaitForEnter(reader)
				continue
			}
			runSpiderFootScan(target)
			utils.WaitForEnter(reader)
		case "3":
			if !ensureLocalOrGlobalToolReady(reader, "maigret") {
				utils.WaitForEnter(reader)
				continue
			}
			target := askTarget(reader, "Username")
			if target == "" {
				fmt.Printf("%sUsername is required.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				continue
			}
			runMaigretLookup(target)
			utils.WaitForEnter(reader)
		case "4":
			return
		default:
			fmt.Printf("%sInvalid option.%s\n", utils.Red, utils.Reset)
			utils.WaitForEnter(reader)
		}
	}
}

func setupOSINTToolsMenu(reader *bufio.Reader) {
	for {
		utils.ClearTerminal()
		printOSINTHeader("Tool Setup and Status")
		printOSINTToolStatus()
		fmt.Printf("\n%s[1] Prepare missing local repos in exec_tools%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[2] Install Sherlock CLI with pip --user%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[3] Install Shodan CLI with pip --user%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[4] Back%s\n", utils.Yellow, utils.Reset)
		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)
		input, ok := readMenuInput(reader)
		if !ok {
			return
		}

		switch input {
		case "1":
			setupRecommendedLocalTools(reader)
			utils.WaitForEnter(reader)
		case "2":
			ensurePythonPackageToolReady(reader, "sherlock", "sherlock-project")
			utils.WaitForEnter(reader)
		case "3":
			ensurePythonPackageToolReady(reader, "shodan", "shodan")
			utils.WaitForEnter(reader)
		case "4":
			return
		default:
			fmt.Printf("%sInvalid option.%s\n", utils.Red, utils.Reset)
			utils.WaitForEnter(reader)
		}
	}
}

func askHostOrDomainTarget(reader *bufio.Reader) string {
	raw := askTarget(reader, "Domain, IP, or URL")
	if raw == "" {
		return ""
	}
	norm, err := normalizeOSINTHostInput(raw)
	if err != nil {
		fmt.Printf("%s%s%s\n", utils.Red, err.Error(), utils.Reset)
		return ""
	}
	if isIPAddressString(norm) {
		return norm
	}
	if isLikelyDomain(norm) {
		return norm
	}
	fmt.Printf("%sInvalid domain or host name.%s\n", utils.Red, utils.Reset)
	return ""
}

func askDomainNameTarget(reader *bufio.Reader) string {
	t := askHostOrDomainTarget(reader)
	if t == "" {
		return ""
	}
	if isIPAddressString(t) {
		fmt.Printf("%sA domain name is required (not an IP address).%s\n", utils.Red, utils.Reset)
		return ""
	}
	return t
}

func askTarget(reader *bufio.Reader, label string) string {
	fmt.Printf("%s%s: %s", utils.Green, label, utils.Reset)
	val, _ := reader.ReadString('\n')
	return strings.TrimSpace(val)
}

func readMenuInput(reader *bufio.Reader) (string, bool) {
	val, err := reader.ReadString('\n')
	val = strings.TrimSpace(val)
	if err != nil && val == "" {
		return "", false
	}
	return val, true
}

func runDNSRecon(target string) {
	if ip := net.ParseIP(target); ip != nil {
		ipStr := ip.String()
		if isToolInstalled("dig") {
			runOSINTCommand("dns-ptr", target, "dig", []string{"+short", "-x", ipStr})
			return
		}
		runOSINTCommand("dns-ptr", target, "nslookup", []string{ipStr})
		return
	}
	if isToolInstalled("dig") {
		runOSINTCommand("dns-a", target, "dig", []string{"+short", "A", target})
		runOSINTCommand("dns-aaaa", target, "dig", []string{"+short", "AAAA", target})
		runOSINTCommand("dns-mx", target, "dig", []string{"+short", "MX", target})
		runOSINTCommand("dns-txt", target, "dig", []string{"+short", "TXT", target})
		runOSINTCommand("dns-ns", target, "dig", []string{"+short", "NS", target})
		return
	}
	runOSINTCommand("dns-a", target, "nslookup", []string{"-type=A", target})
	runOSINTCommand("dns-aaaa", target, "nslookup", []string{"-type=AAAA", target})
	runOSINTCommand("dns-mx", target, "nslookup", []string{"-type=MX", target})
	runOSINTCommand("dns-txt", target, "nslookup", []string{"-type=TXT", target})
	runOSINTCommand("dns-ns", target, "nslookup", []string{"-type=NS", target})
}

func runSubdomainEnum(target string) {
	switch {
	case isToolInstalled("subfinder"):
		runOSINTCommand("subfinder", target, "subfinder", []string{"-d", target, "-silent"})
	case isToolInstalled("assetfinder"):
		runOSINTCommand("assetfinder", target, "assetfinder", []string{"--subs-only", target})
	case isToolInstalled("amass"):
		runOSINTCommand("amass", target, "amass", []string{"enum", "-passive", "-d", target})
	default:
		recordAndPrintError("subdomain-enum", target, buildMissingToolMessage("subdomain-enum"), time.Now())
	}
}

func runMaigretLookup(target string) {
	args := []string{"-a", "--html", target}

	if isToolInstalled("maigret") {
		runOSINTCommand("maigret", target, "maigret", args)
		return
	}

	repoPath := filepath.Join(pathExecTools(), "maigret")
	if dirExists(repoPath) {
		if runLocalPythonModuleCommand("maigret", target, repoPath, "maigret", args) {
			return
		}
	}

	recordAndPrintError("maigret", target, buildMissingToolMessage("maigret"), time.Now())
}

func runTheHarvester(target string) {
	args := []string{"-d", target, "-b", "crtsh", "-l", "500"}

	if isToolInstalled("theHarvester") {
		runOSINTCommand("theharvester", target, "theHarvester", args)
		return
	}

	if runLocalPythonModuleCommand("theharvester", target, filepath.Join(pathExecTools(), "theHarvester"), "theHarvester", args) {
		return
	}

	recordAndPrintError("theharvester", target, buildMissingToolMessage("theHarvester"), time.Now())
}

func runReconNG(target string) {
	script := strings.Join([]string{
		"marketplace refresh",
		"marketplace install recon/domains-hosts/hackertarget",
		"modules load recon/domains-hosts/hackertarget",
		"options set SOURCE " + target,
		"run",
		"show hosts",
		"exit",
	}, "\n")

	tmp := filepath.Join(os.TempDir(), "reconng_script.rc")
	if err := os.WriteFile(tmp, []byte(script), 0644); err != nil {
		fmt.Printf("%sFailed to prepare recon-ng script: %v%s\n", utils.Red, err, utils.Reset)
		return
	}

	if isToolInstalled("recon-ng") {
		runOSINTCommand("recon-ng", target, "recon-ng", []string{"-r", tmp})
		return
	}

	if runLocalPythonScriptCommand("recon-ng", target, filepath.Join(pathExecTools(), "recon-ng"), []string{"recon-ng", "recon-ng.py"}, []string{"-r", tmp}) {
		return
	}

	recordAndPrintError("recon-ng", target, buildMissingToolMessage("recon-ng"), time.Now())
}

func runSpiderFootScan(target string) {
	if isToolInstalled("spiderfoot") {
		runOSINTCommand("spiderfoot", target, "spiderfoot", []string{"-s", target, "-q"})
		return
	}
	if isToolInstalled("sf.py") {
		runOSINTCommand("spiderfoot", target, "sf.py", []string{"-s", target, "-q"})
		return
	}

	if runLocalPythonScriptCommand("spiderfoot", target, filepath.Join(pathExecTools(), "spiderfoot"), []string{"sf.py", "spiderfoot.py"}, []string{"-s", target, "-q"}) {
		return
	}

	recordAndPrintError("spiderfoot", target, buildMissingToolMessage("spiderfoot"), time.Now())
}

func runShodanInternetDB(ip, label string) {
	if strings.TrimSpace(label) == "" {
		label = ip
	}
	start := time.Now()
	endpoint := "https://internetdb.shodan.io/" + url.PathEscape(ip)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(endpoint)
	if err != nil {
		msg := fmt.Sprintf("InternetDB request failed: %v", err)
		recordAndPrintError("shodan-internetdb", label, msg, start)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		msg := fmt.Sprintf("InternetDB read failed: %v", err)
		recordAndPrintError("shodan-internetdb", label, msg, start)
		return
	}

	outFile, saveErr := saveOSINTOutput("shodan-internetdb", label, body)
	if saveErr != nil {
		msg := fmt.Sprintf("Failed to save output: %v", saveErr)
		recordAndPrintError("shodan-internetdb", label, msg, start)
		return
	}

	rec := OSINTRecord{
		Tool:            "shodan-internetdb",
		Target:          label,
		Status:          "ok",
		Summary:         "InternetDB lookup completed for " + ip + ".",
		OutputFile:      outFile,
		DurationSeconds: time.Since(start).Seconds(),
		RanAt:           time.Now(),
	}
	recordOSINT(rec)
	fmt.Printf("%sSaved InternetDB result to %s%s\n", utils.Green, outFile, utils.Reset)
}

type webProbeResult struct {
	URL        string
	FinalURL   string
	Status     string
	StatusCode int
	Server     string
	Title      string
	TLSNames   []string
	Error      string
}

func normalizeOSINTHostInput(raw string) (string, error) {
	q := strings.TrimSpace(raw)
	if q == "" {
		return "", errors.New("empty input")
	}
	q = strings.Trim(q, `"'`)
	if utils.IsValidIPv4(q) {
		return q, nil
	}
	if ip := net.ParseIP(strings.Trim(q, "[]")); ip != nil {
		return ip.String(), nil
	}
	if strings.Contains(q, "://") {
		u, err := url.Parse(q)
		if err != nil {
			return "", err
		}
		if u.Host != "" {
			q = u.Host
		}
	}
	if h, _, err := net.SplitHostPort(q); err == nil {
		q = h
	}
	q = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(q)), ".")
	if q == "" {
		return "", errors.New("could not parse host")
	}
	if utils.IsValidIPv4(q) {
		return q, nil
	}
	if ip := net.ParseIP(q); ip != nil {
		return ip.String(), nil
	}
	return q, nil
}

func isIPAddressString(s string) bool {
	if utils.IsValidIPv4(s) {
		return true
	}
	return net.ParseIP(s) != nil
}

func resolvedIPForOSINT(query string) (string, error) {
	norm, err := normalizeOSINTHostInput(query)
	if err != nil {
		return "", err
	}
	if utils.IsValidIPv4(norm) {
		return norm, nil
	}
	if ip := net.ParseIP(norm); ip != nil {
		return ip.String(), nil
	}
	ips, err := net.LookupIP(norm)
	if err != nil {
		return "", err
	}
	for _, ipa := range ips {
		if v4 := ipa.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	for _, ipa := range ips {
		if ipa.To4() == nil {
			return ipa.String(), nil
		}
	}
	return "", fmt.Errorf("no IP address for %s", norm)
}

func ipBracketedForURL(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}
	if ip.To4() != nil {
		return ip.String()
	}
	return "[" + ip.String() + "]"
}

func runIPWebFinder(resolvedIP, query string) {
	start := time.Now()
	if strings.TrimSpace(query) == "" {
		query = resolvedIP
	}
	var report strings.Builder
	report.WriteString("REVERSE DNS AND WEB FINDER\n")
	report.WriteString("Input: " + query + "\n")
	report.WriteString("Resolved IP: " + resolvedIP + "\n")
	report.WriteString("Started: " + time.Now().Format("2006-01-02 15:04:05") + "\n\n")

	ptrs, err := net.LookupAddr(resolvedIP)
	if err != nil {
		report.WriteString("Reverse DNS: no PTR records found (" + err.Error() + ")\n")
	} else {
		ptrs = normalizeHostnames(ptrs)
		report.WriteString("Reverse DNS records:\n")
		for _, ptr := range ptrs {
			report.WriteString("- " + ptr + "\n")
		}
	}

	candidates := buildIPWebCandidates(resolvedIP, ptrs)
	results := probeWebTargets(candidates, 7*time.Second)
	writeWebProbeResults(&report, results)
	saveWebFinderResult("reverse-web-finder", query, report.String(), start, results)
}

func runDomainWebFinder(domain string) {
	start := time.Now()
	var report strings.Builder
	report.WriteString("DOMAIN WEBSITE AND IP MAPPING\n")
	report.WriteString("Target domain: " + domain + "\n")
	report.WriteString("Started: " + time.Now().Format("2006-01-02 15:04:05") + "\n\n")

	if cname, err := net.LookupCNAME(domain); err == nil && strings.TrimSuffix(cname, ".") != domain {
		report.WriteString("CNAME: " + strings.TrimSuffix(cname, ".") + "\n")
	}

	ips, err := net.LookupIP(domain)
	ipStrings := make([]string, 0, len(ips))
	if err != nil {
		report.WriteString("IP resolution: failed (" + err.Error() + ")\n")
	} else {
		report.WriteString("Resolved IP addresses:\n")
		for _, ip := range ips {
			ipText := ip.String()
			ipStrings = append(ipStrings, ipText)
			report.WriteString("- " + ipText + "\n")
		}
	}

	if len(ipStrings) > 0 {
		report.WriteString("\nReverse DNS for resolved IPs:\n")
		for _, ip := range ipStrings {
			ptrs, ptrErr := net.LookupAddr(ip)
			if ptrErr != nil {
				report.WriteString("- " + ip + ": none\n")
				continue
			}
			report.WriteString("- " + ip + ": " + strings.Join(normalizeHostnames(ptrs), ", ") + "\n")
		}
	}

	candidates := buildDomainWebCandidates(domain, ipStrings)
	results := probeWebTargets(candidates, 7*time.Second)
	writeWebProbeResults(&report, results)
	saveWebFinderResult("domain-web-finder", domain, report.String(), start, results)
}

func runEmailDomainFootprint(email string) {
	start := time.Now()
	parts := strings.Split(strings.TrimSpace(email), "@")
	if len(parts) != 2 || !isLikelyDomain(parts[1]) {
		recordAndPrintError("email-domain-footprint", email, "Invalid email domain.", start)
		return
	}
	domain := strings.ToLower(parts[1])

	var report strings.Builder
	report.WriteString("EMAIL DOMAIN FOOTPRINT\n")
	report.WriteString("Email: " + email + "\n")
	report.WriteString("Domain: " + domain + "\n")
	report.WriteString("Started: " + time.Now().Format("2006-01-02 15:04:05") + "\n\n")

	if hosts, err := net.LookupHost(domain); err == nil && len(hosts) > 0 {
		report.WriteString("Domain hosts:\n")
		for _, host := range dedupeKeepOrder(hosts) {
			report.WriteString("- " + host + "\n")
		}
	} else if err != nil {
		report.WriteString("Domain hosts: lookup failed (" + err.Error() + ")\n")
	}

	if mxRecords, err := net.LookupMX(domain); err == nil && len(mxRecords) > 0 {
		sort.Slice(mxRecords, func(i, j int) bool { return mxRecords[i].Pref < mxRecords[j].Pref })
		report.WriteString("\nMX records:\n")
		for _, mx := range mxRecords {
			report.WriteString(fmt.Sprintf("- %s preference=%d\n", strings.TrimSuffix(mx.Host, "."), mx.Pref))
		}
	} else if err != nil {
		report.WriteString("\nMX records: lookup failed (" + err.Error() + ")\n")
	} else {
		report.WriteString("\nMX records: none found\n")
	}

	if nsRecords, err := net.LookupNS(domain); err == nil && len(nsRecords) > 0 {
		report.WriteString("\nName servers:\n")
		for _, ns := range nsRecords {
			report.WriteString("- " + strings.TrimSuffix(ns.Host, ".") + "\n")
		}
	}

	txtRecords, txtErr := net.LookupTXT(domain)
	spfRecords := filterTXTRecords(txtRecords, "v=spf1")
	report.WriteString("\nSPF records:\n")
	if txtErr != nil {
		report.WriteString("- lookup failed: " + txtErr.Error() + "\n")
	} else if len(spfRecords) == 0 {
		report.WriteString("- none found\n")
	} else {
		for _, txt := range spfRecords {
			report.WriteString("- " + txt + "\n")
		}
	}

	dmarcRecords, dmarcErr := net.LookupTXT("_dmarc." + domain)
	dmarcRecords = filterTXTRecords(dmarcRecords, "v=DMARC1")
	report.WriteString("\nDMARC records:\n")
	if dmarcErr != nil {
		report.WriteString("- lookup failed: " + dmarcErr.Error() + "\n")
	} else if len(dmarcRecords) == 0 {
		report.WriteString("- none found\n")
	} else {
		for _, txt := range dmarcRecords {
			report.WriteString("- " + txt + "\n")
		}
	}

	status := "ok"
	summary := "Email domain footprint completed."
	if len(spfRecords) == 0 || len(dmarcRecords) == 0 {
		status = "warning"
		summary = "Email domain footprint completed with missing SPF or DMARC records."
	}

	outFile, saveErr := saveOSINTOutput("email-domain-footprint", email, []byte(report.String()))
	if saveErr != nil {
		recordAndPrintError("email-domain-footprint", email, fmt.Sprintf("Failed to save output: %v", saveErr), start)
		return
	}

	recordOSINT(OSINTRecord{
		Tool:            "email-domain-footprint",
		Target:          email,
		Status:          status,
		Summary:         summary,
		OutputFile:      outFile,
		DurationSeconds: time.Since(start).Seconds(),
		RanAt:           time.Now(),
	})
	fmt.Printf("%sSaved email domain footprint to %s%s\n", utils.Green, outFile, utils.Reset)
	printOSINTOutputPreview("email-domain-footprint", []byte(report.String()))
}

func filterTXTRecords(records []string, prefix string) []string {
	prefix = strings.ToLower(prefix)
	var out []string
	for _, record := range records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(record)), prefix) {
			out = append(out, record)
		}
	}
	return dedupeKeepOrder(out)
}

func normalizeHostnames(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSuffix(strings.TrimSpace(value), ".")
		if value != "" {
			out = append(out, value)
		}
	}
	return dedupeKeepOrder(out)
}

func buildIPWebCandidates(ip string, ptrs []string) []string {
	lit := ipBracketedForURL(ip)
	candidates := []string{"https://" + lit, "http://" + lit}
	for _, host := range ptrs {
		candidates = append(candidates, "https://"+host, "http://"+host)
	}
	return dedupeKeepOrder(limitStrings(candidates, 12))
}

func buildDomainWebCandidates(domain string, ips []string) []string {
	candidates := []string{"https://" + domain, "http://" + domain}
	if !strings.HasPrefix(domain, "www.") {
		candidates = append(candidates, "https://www."+domain, "http://www."+domain)
	}
	for _, ip := range ips {
		lit := ipBracketedForURL(ip)
		candidates = append(candidates, "https://"+lit, "http://"+lit)
	}
	return dedupeKeepOrder(limitStrings(candidates, 12))
}

func limitStrings(values []string, max int) []string {
	if len(values) <= max {
		return values
	}
	return values[:max]
}

func probeWebTargets(candidates []string, timeout time.Duration) []webProbeResult {
	results := make([]webProbeResult, len(candidates))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)

	for i, candidate := range candidates {
		wg.Add(1)
		go func(idx int, rawURL string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = probeWebTarget(rawURL, timeout)
		}(i, candidate)
	}

	wg.Wait()
	return results
}

func probeWebTarget(rawURL string, timeout time.Duration) webProbeResult {
	result := webProbeResult{URL: rawURL}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Timeout: timeout, Transport: transport}

	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("user-agent", "ECLIPSE-OSINT")
	req.Header.Set("range", "bytes=0-65535")

	resp, err := client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	result.Status = resp.Status
	result.StatusCode = resp.StatusCode
	result.FinalURL = resp.Request.URL.String()
	result.Server = resp.Header.Get("server")
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	result.Title = extractHTMLTitle(string(body))
	result.TLSNames = tlsNamesFromResponse(resp)
	return result
}

func tlsNamesFromResponse(resp *http.Response) []string {
	if resp == nil || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil
	}
	cert := resp.TLS.PeerCertificates[0]
	values := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses)+2)
	if cert.Subject.CommonName != "" {
		values = append(values, "CN="+cert.Subject.CommonName)
	}
	for _, name := range cert.DNSNames {
		values = append(values, name)
	}
	for _, ip := range cert.IPAddresses {
		values = append(values, ip.String())
	}
	if !cert.NotAfter.IsZero() {
		values = append(values, "expires="+cert.NotAfter.Format("2006-01-02"))
	}
	return dedupeKeepOrder(values)
}

func writeWebProbeResults(report *strings.Builder, results []webProbeResult) {
	report.WriteString("\nWeb probes:\n")
	if len(results) == 0 {
		report.WriteString("- no candidates generated\n")
		return
	}
	for _, result := range results {
		report.WriteString("- " + result.URL + "\n")
		if result.Error != "" {
			report.WriteString("  error: " + result.Error + "\n")
			continue
		}
		report.WriteString("  status: " + result.Status + "\n")
		if result.FinalURL != "" && result.FinalURL != result.URL {
			report.WriteString("  final_url: " + result.FinalURL + "\n")
		}
		if result.Server != "" {
			report.WriteString("  server: " + result.Server + "\n")
		}
		if result.Title != "" {
			report.WriteString("  title: " + result.Title + "\n")
		}
		if len(result.TLSNames) > 0 {
			report.WriteString("  tls: " + strings.Join(result.TLSNames, ", ") + "\n")
		}
	}
}

func saveWebFinderResult(toolName, target, report string, start time.Time, results []webProbeResult) {
	status := "warning"
	summary := "No responsive web endpoints found."
	for _, result := range results {
		if result.StatusCode > 0 && result.StatusCode < 600 {
			status = "ok"
			summary = "Web finder completed with responsive endpoint(s)."
			break
		}
	}

	outFile, saveErr := saveOSINTOutput(toolName, target, []byte(report))
	if saveErr != nil {
		recordAndPrintError(toolName, target, fmt.Sprintf("Failed to save output: %v", saveErr), start)
		return
	}

	recordOSINT(OSINTRecord{
		Tool:            toolName,
		Target:          target,
		Status:          status,
		Summary:         summary,
		OutputFile:      outFile,
		DurationSeconds: time.Since(start).Seconds(),
		RanAt:           time.Now(),
	})
	fmt.Printf("%sSaved web finder result to %s%s\n", utils.Green, outFile, utils.Reset)
	printOSINTOutputPreview(toolName, []byte(report))
}

func runOSINTCommand(toolName, target, cmdName string, args []string) {
	start := time.Now()
	toolWorkDir := ""
	if strings.EqualFold(strings.TrimSpace(toolName), "sherlock") {
		if tmpDir, tmpErr := os.MkdirTemp("", "g0-sherlock-*"); tmpErr == nil {
			toolWorkDir = tmpDir
			defer os.RemoveAll(tmpDir)
		}
	}
	if normalizeToolKey(toolName) == "maigret" {
		toolWorkDir = maigretOutputDir()
	}

	resolvedCmd, err := resolveToolPath(cmdName)
	if err != nil {
		if isPythonModuleFallbackTool(cmdName) {
			pyCmd, pyArgs, pyErr := resolvePythonModuleCommand(cmdName, args)
			if pyErr == nil {
				cmd := exec.Command(pyCmd, pyArgs...)
				if toolWorkDir != "" {
					cmd.Dir = toolWorkDir
				}
				executeOSINTCommand(toolName, target, cmdName, cmd, start)
				return
			}
		}
		recordAndPrintError(toolName, target, buildMissingToolMessage(cmdName), start)
		return
	}

	cmd := exec.Command(resolvedCmd, args...)
	if toolWorkDir != "" {
		cmd.Dir = toolWorkDir
	}
	executeOSINTCommand(toolName, target, cmdName, cmd, start)
}

func executeOSINTCommand(toolName, target, cmdName string, cmd *exec.Cmd, start time.Time) {
	if cmd == nil {
		recordAndPrintError(toolName, target, "Internal error: command is nil.", start)
		return
	}

	cmd.Env = processEnvWithExpandedPath()
	output, err, timedOut := runCommandCaptureWithProgress(toolName+" -> "+target, cmd, commandTimeoutForTool(toolName))
	if timedOut {
		err = fmt.Errorf("command timed out after %s", commandTimeoutForTool(toolName).Round(time.Second))
		output = append(output, []byte("\n"+err.Error()+"\n")...)
	}
	if err != nil && shouldAttemptPkgResourcesFix(cmdName, output) {
		hint := manualRepairHintForTool(cmdName)
		if hint != "" {
			output = append(output, []byte("\nManual fix: "+hint+"\n")...)
		}
	}

	if len(output) == 0 {
		output = []byte("(no output)\n")
	}
	processedOutput := extractActionableOutput(toolName, output)
	if len(strings.TrimSpace(string(processedOutput))) == 0 {
		processedOutput = []byte("No actionable results found in tool output.\n")
	}

	outFile, saveErr := saveOSINTOutput(toolName, target, processedOutput)
	if saveErr != nil {
		recordAndPrintError(toolName, target, fmt.Sprintf("Failed to save output: %v", saveErr), start)
		return
	}

	status := "ok"
	summary := "Command completed."
	if err != nil {
		status = "warning"
		summary = fmt.Sprintf("Command exited with error: %v", err)
	}

	recordOSINT(OSINTRecord{
		Tool:            toolName,
		Target:          target,
		Status:          status,
		Summary:         summary,
		OutputFile:      outFile,
		DurationSeconds: time.Since(start).Seconds(),
		RanAt:           time.Now(),
	})

	if status == "ok" {
		fmt.Printf("%sSaved output to %s%s\n", utils.Green, outFile, utils.Reset)
	} else {
		fmt.Printf("%s%s%s\n", utils.Yellow, summary, utils.Reset)
		fmt.Printf("%sOutput saved to %s%s\n", utils.Yellow, outFile, utils.Reset)
	}
	printOSINTOutputPreview(toolName, processedOutput)
}

func runSetupCommand(cmd *exec.Cmd) ([]byte, error) {
	if cmd == nil {
		return nil, errors.New("nil setup command")
	}
	cmd.Env = processEnvWithExpandedPath()
	output, err, _ := runCommandCaptureWithProgressLive("setup: "+cmd.String(), cmd, 15*time.Minute, true)
	return output, err
}

func runCommandCaptureWithProgress(label string, cmd *exec.Cmd, timeout time.Duration) ([]byte, error, bool) {
	return runCommandCaptureWithProgressLive(label, cmd, timeout, false)
}

func runCommandCaptureWithProgressLive(label string, cmd *exec.Cmd, timeout time.Duration, liveOutput bool) ([]byte, error, bool) {
	if cmd == nil {
		return nil, errors.New("nil command"), false
	}
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	if cmd.Env == nil {
		cmd.Env = processEnvWithExpandedPath()
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err, false
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err, false
	}

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	var wg sync.WaitGroup
	if liveOutput {
		cmd.Stdin = os.Stdin
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		var writer io.Writer = &stdoutBuf
		if liveOutput {
			writer = io.MultiWriter(&stdoutBuf, os.Stdout)
		}
		_, _ = io.Copy(writer, stdout)
	}()
	go func() {
		defer wg.Done()
		var writer io.Writer = &stderrBuf
		if liveOutput {
			writer = io.MultiWriter(&stderrBuf, os.Stderr)
		}
		_, _ = io.Copy(writer, stderr)
	}()

	if err := cmd.Start(); err != nil {
		return nil, err, false
	}

	done := make(chan error, 1)
	go func() {
		waitErr := cmd.Wait()
		wg.Wait()
		done <- waitErr
	}()

	started := time.Now()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case err := <-done:
			return combineCommandOutput(stdoutBuf.Bytes(), stderrBuf.Bytes()), err, false
		case <-ticker.C:
			fmt.Printf("%sStill running:%s %s (%.0fs elapsed)\n", utils.Blue, utils.Reset, label, time.Since(started).Seconds())
		case <-timer.C:
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			err := <-done
			return combineCommandOutput(stdoutBuf.Bytes(), stderrBuf.Bytes()), err, true
		}
	}
}

func combineCommandOutput(stdout, stderr []byte) []byte {
	output := make([]byte, 0, len(stdout)+len(stderr)+1)
	output = append(output, stdout...)
	if len(stdout) > 0 && len(stderr) > 0 && stdout[len(stdout)-1] != '\n' {
		output = append(output, '\n')
	}
	output = append(output, stderr...)
	return output
}

func commandTimeoutForTool(toolName string) time.Duration {
	switch strings.ToLower(strings.TrimSpace(toolName)) {
	case "dns-a", "dns-aaaa", "dns-mx", "dns-txt", "dns-ns", "dns-ptr":
		return 20 * time.Second
	case "whois", "shodan-cli":
		return 45 * time.Second
	case "sherlock", "theharvester", "maigret":
		return 3 * time.Minute
	case "recon-ng", "spiderfoot":
		return 4 * time.Minute
	default:
		return 2 * time.Minute
	}
}

func saveOSINTOutput(toolName, target string, data []byte) (string, error) {
	if err := os.MkdirAll(pathOSINTReports(), 0755); err != nil {
		return "", err
	}
	filename := buildOSINTOutputName(toolName, target, "txt")
	fullPath := filepath.Join(pathOSINTReports(), filename)
	if err := os.WriteFile(fullPath, data, 0644); err != nil {
		return "", err
	}
	return fullPath, nil
}

func buildOSINTOutputName(toolName, target, ext string) string {
	safeTarget := sanitizeForFilename(target)
	timestamp := time.Now().Format("20060102_150405")
	return toolName + "_" + safeTarget + "_" + timestamp + "." + ext
}

func sanitizeForFilename(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.ReplaceAll(v, " ", "_")
	v = strings.ReplaceAll(v, "/", "_")
	v = strings.ReplaceAll(v, "\\", "_")
	v = strings.ReplaceAll(v, ":", "_")
	v = strings.ReplaceAll(v, "@", "_at_")
	if v == "" {
		return "target"
	}
	return v
}

func recordAndPrintError(toolName, target, message string, start time.Time) {
	recordOSINT(OSINTRecord{
		Tool:            toolName,
		Target:          target,
		Status:          "error",
		Summary:         message,
		DurationSeconds: time.Since(start).Seconds(),
		RanAt:           time.Now(),
	})
	fmt.Printf("%s%s%s\n", utils.Red, message, utils.Reset)
}

func recordOSINT(rec OSINTRecord) {
	history := OSINTHistory{}
	raw, err := os.ReadFile(pathOSINTResults())
	if err == nil {
		_ = json.Unmarshal(raw, &history)
	}
	history.Records = append(history.Records, rec)
	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		fmt.Printf("%sCould not serialize OSINT history: %v%s\n", utils.Red, err, utils.Reset)
		return
	}
	if err := os.WriteFile(pathOSINTResults(), data, 0644); err != nil {
		fmt.Printf("%sCould not save OSINT history: %v%s\n", utils.Red, err, utils.Reset)
	}
}

func viewOSINTHistory() {
	utils.ClearTerminal()
	fmt.Printf("\n%s=== OSINT HISTORY ===%s\n\n", utils.Blue, utils.Reset)

	data, err := os.ReadFile(pathOSINTResults())
	if err != nil {
		fmt.Printf("%sNo OSINT history found.%s\n", utils.Red, utils.Reset)
		return
	}

	var history OSINTHistory
	if err := json.Unmarshal(data, &history); err != nil {
		fmt.Printf("%sInvalid OSINT history format: %v%s\n", utils.Red, err, utils.Reset)
		return
	}

	if len(history.Records) == 0 {
		fmt.Printf("%sOSINT history is empty.%s\n", utils.Yellow, utils.Reset)
		return
	}

	for i, rec := range history.Records {
		color := utils.Green
		if rec.Status == "warning" {
			color = utils.Yellow
		}
		if rec.Status == "error" {
			color = utils.Red
		}
		fmt.Printf("%s[%d] %s | %s | %s | %.2fs%s\n", color, i+1, rec.RanAt.Format("2006-01-02 15:04:05"), rec.Tool, rec.Target, rec.DurationSeconds, utils.Reset)
		fmt.Printf("    Status: %s\n", rec.Status)
		fmt.Printf("    Summary: %s\n", rec.Summary)
		if rec.OutputFile != "" {
			fmt.Printf("    Output: %s\n", rec.OutputFile)
		}
		fmt.Println()
	}
}

func isToolInstalled(name string) bool {
	_, err := resolveToolPath(name)
	if err == nil {
		return true
	}
	if isPythonModuleFallbackTool(name) {
		_, _, pyErr := resolvePythonModuleCommand(name, nil)
		return pyErr == nil
	}
	return false
}

func isLikelyDomain(v string) bool {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" || strings.Contains(v, " ") || strings.Contains(v, "@") {
		return false
	}
	if utils.IsValidIPv4(v) || net.ParseIP(v) != nil {
		return false
	}
	return osintDomainHostRegexp.MatchString(v)
}

func isLikelyEmail(v string) bool {
	return osintEmailRegexp.MatchString(strings.TrimSpace(v))
}

func ensureDependenciesForOSINTOption(reader *bufio.Reader, option string) bool {
	required := requiredDependenciesForOption(option)
	return ensureDependencyRequirements(reader, required)
}

func ensureDependencyRequirements(reader *bufio.Reader, required []string) bool {
	if len(required) == 0 {
		return true
	}

	missing := missingTools(required)
	if len(missing) == 0 {
		return true
	}

	fmt.Printf("%sMissing dependencies for this option: %s%s\n", utils.Yellow, strings.Join(formatRequirementLabels(missing), ", "), utils.Reset)
	installCommands := buildDependencyInstallCommands(missing)
	if len(installCommands) == 0 {
		printDependencyInstallHints(missing)
		return false
	}

	fmt.Printf("%sInstall only these dependencies now? (y/N): %s", utils.Yellow, utils.Reset)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer != "y" && answer != "yes" {
		printDependencyInstallHints(missing)
		return false
	}

	runDependencyInstallCommands(installCommands)
	stillMissing := missingTools(required)
	if len(stillMissing) > 0 {
		fmt.Printf("%sStill missing after setup: %s%s\n", utils.Red, strings.Join(formatRequirementLabels(stillMissing), ", "), utils.Reset)
		printDependencyInstallHints(stillMissing)
		return false
	}
	return true
}

func requiredDependenciesForOption(option string) []string {
	switch strings.ToLower(strings.TrimSpace(option)) {
	case "whois":
		return []string{"whois"}
	case "dns":
		return []string{"dig|nslookup"}
	case "python-pip":
		return []string{"python3|python|py", "pip3|pip"}
	case "git":
		return []string{"git"}
	case "go":
		return []string{"go"}
	case "3", "5", "7", "13":
		return []string{"python3|python|py", "pip3|pip"}
	default:
		return nil
	}
}

func requiredAPIKeysForOption(option string) []string {
	switch strings.ToLower(strings.TrimSpace(option)) {
	case "5", "shodan-cli":
		return []string{"SHODAN_API_KEY"}
	default:
		return nil
	}
}

func ensureAPIKeysForOption(reader *bufio.Reader, option string) bool {
	required := requiredAPIKeysForOption(option)
	if len(required) == 0 {
		return true
	}

	missing := missingAPIKeys(required)
	if len(missing) == 0 {
		return true
	}

	fmt.Printf("%sMissing required API keys for this option:%s\n", utils.Yellow, utils.Reset)
	for _, key := range missing {
		link := apiKeyHelpLinks[key]
		if link == "" {
			link = "No link available."
		}
		fmt.Printf("%s- %s%s\n", utils.Yellow, key, utils.Reset)
		fmt.Printf("  Create key here: %s\n", link)
	}

	fmt.Printf("\n%sDo you want to enter these API keys now? (y/N): %s", utils.Yellow, utils.Reset)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer != "y" && answer != "yes" {
		fmt.Printf("%sOperation cancelled. API key(s) are required.%s\n", utils.Red, utils.Reset)
		return false
	}

	store := loadAPIKeyStore()
	for _, key := range missing {
		fmt.Printf("%sEnter value for %s: %s", utils.Green, key, utils.Reset)
		value, _ := reader.ReadString('\n')
		value = strings.TrimSpace(value)
		if value == "" {
			fmt.Printf("%sKey %s left empty. Cannot continue.%s\n", utils.Red, key, utils.Reset)
			return false
		}
		store[key] = value
		_ = os.Setenv(key, value)
	}

	if err := saveAPIKeyStore(store); err != nil {
		fmt.Printf("%sFailed to save API keys: %v%s\n", utils.Red, err, utils.Reset)
		return false
	}
	fmt.Printf("%sAPI keys saved successfully.%s\n", utils.Green, utils.Reset)
	return true
}

func missingAPIKeys(keys []string) []string {
	var missing []string
	for _, k := range keys {
		if strings.TrimSpace(os.Getenv(k)) == "" {
			missing = append(missing, k)
		}
	}
	return missing
}

func manageAPIKeys(reader *bufio.Reader) {
	fmt.Printf("\n%s=== API KEY MANAGER ===%s\n", utils.Blue, utils.Reset)
	store := loadAPIKeyStore()

	allKeys := []string{"SHODAN_API_KEY"}
	for _, k := range allKeys {
		val := strings.TrimSpace(os.Getenv(k))
		if val == "" {
			val = strings.TrimSpace(store[k])
		}
		status := "missing"
		if val != "" {
			status = "configured"
		}
		fmt.Printf("%s- %s: %s%s\n", utils.Green, k, status, utils.Reset)
		fmt.Printf("  Get key: %s\n", apiKeyHelpLinks[k])
	}

	fmt.Printf("\n%s[1] Set/Update keys%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[2] Clear all saved keys%s\n", utils.Red, utils.Reset)
	fmt.Printf("%s[3] Back%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("%sOption: %s", utils.Green, utils.Reset)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	switch input {
	case "1":
		for _, k := range allKeys {
			fmt.Printf("%sEnter %s (blank to keep current): %s", utils.Green, k, utils.Reset)
			v, _ := reader.ReadString('\n')
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			store[k] = v
			_ = os.Setenv(k, v)
		}
		if err := saveAPIKeyStore(store); err != nil {
			fmt.Printf("%sFailed to save keys: %v%s\n", utils.Red, err, utils.Reset)
			return
		}
		fmt.Printf("%sAPI keys updated.%s\n", utils.Green, utils.Reset)
	case "2":
		if err := os.Remove(pathOSINTAPIKeys()); err != nil && !os.IsNotExist(err) {
			fmt.Printf("%sFailed to clear key store: %v%s\n", utils.Red, err, utils.Reset)
			return
		}
		for _, k := range allKeys {
			_ = os.Unsetenv(k)
		}
		fmt.Printf("%sSaved API keys cleared.%s\n", utils.Green, utils.Reset)
	default:
		return
	}
}

func loadAPIKeyStore() map[string]string {
	data, err := os.ReadFile(pathOSINTAPIKeys())
	if err != nil {
		return map[string]string{}
	}
	store := map[string]string{}
	if err := json.Unmarshal(data, &store); err != nil {
		return map[string]string{}
	}
	return store
}

func saveAPIKeyStore(store map[string]string) error {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(pathOSINTAPIKeys(), data, 0600)
}

func loadStoredAPIKeysIntoEnv() {
	store := loadAPIKeyStore()
	for k, v := range store {
		if strings.TrimSpace(v) != "" {
			_ = os.Setenv(k, v)
		}
	}
}

type localToolSpec struct {
	Key         string
	DisplayName string
	CommandName string
	RepoURL     string
}

func ensureExecToolsDir() {
	if dirExists(pathLegacyOSINTTools()) && !dirExists(pathExecTools()) {
		if err := os.Rename(pathLegacyOSINTTools(), pathExecTools()); err != nil {
			fmt.Printf("%sCould not migrate %s to %s: %v%s\n", utils.Yellow, pathLegacyOSINTTools(), pathExecTools(), err, utils.Reset)
		}
	}
	if err := os.MkdirAll(pathExecTools(), 0755); err != nil {
		fmt.Printf("%sCould not create %s: %v%s\n", utils.Red, pathExecTools(), err, utils.Reset)
	}
}

func localOSINTToolSpecs() []localToolSpec {
	return []localToolSpec{
		{Key: "maigret", DisplayName: "Maigret", CommandName: "maigret", RepoURL: "https://github.com/soxoj/maigret.git"},
		{Key: "theharvester", DisplayName: "theHarvester", CommandName: "theHarvester", RepoURL: "https://github.com/laramies/theHarvester.git"},
		{Key: "recon-ng", DisplayName: "Recon-ng", CommandName: "recon-ng", RepoURL: "https://github.com/lanmaster53/recon-ng.git"},
		{Key: "spiderfoot", DisplayName: "SpiderFoot", CommandName: "spiderfoot", RepoURL: "https://github.com/smicallef/spiderfoot.git"},
	}
}

func localOSINTToolSpec(tool string) (localToolSpec, bool) {
	key := normalizeToolKey(tool)
	for _, spec := range localOSINTToolSpecs() {
		if spec.Key == key || strings.EqualFold(spec.CommandName, tool) {
			return spec, true
		}
	}
	return localToolSpec{}, false
}

func ensureLocalOrGlobalToolReady(reader *bufio.Reader, tool string) bool {
	spec, ok := localOSINTToolSpec(tool)
	if !ok {
		fmt.Printf("%sNo setup profile exists for %s.%s\n", utils.Red, tool, utils.Reset)
		return false
	}

	if isToolInstalled(spec.CommandName) || isToolInstalled(spec.Key) {
		return true
	}

	repoPath := toolLocalRepoPath(spec.Key)
	if !dirExists(repoPath) {
		fmt.Printf("%s%s is not installed globally and was not found in %s.%s\n", utils.Yellow, spec.DisplayName, pathExecTools(), utils.Reset)
		if !promptYesNo(reader, "Download it into "+repoPath+" now?") {
			fmt.Printf("%sCancelled. %s needs to be installed before this option can run.%s\n", utils.Yellow, spec.DisplayName, utils.Reset)
			return false
		}
		if !ensureDependencyRequirements(reader, []string{"git"}) {
			return false
		}
		if !cloneLocalTool(spec) {
			return false
		}
	}

	if localPythonToolReady(spec.Key) {
		return true
	}

	fmt.Printf("%sLocal repo found, but its Python environment is not ready: %s%s\n", utils.Yellow, repoPath, utils.Reset)
	if !promptYesNo(reader, "Create/update the local .venv for "+spec.DisplayName+"?") {
		return false
	}
	if !ensureDependencyRequirements(reader, []string{"python3|python|py", "pip3|pip"}) {
		return false
	}
	if !setupLocalPythonTool(spec) {
		return false
	}
	return localPythonToolReady(spec.Key)
}

func localPythonToolReady(tool string) bool {
	repoPath := toolLocalRepoPath(tool)
	if !dirExists(repoPath) {
		return false
	}
	pythonPath, _ := venvPaths(filepath.Join(repoPath, ".venv"))
	return fileExists(pythonPath)
}

func cloneLocalTool(spec localToolSpec) bool {
	ensureExecToolsDir()
	base := pathExecTools()
	if !isDirWritable(base) {
		fmt.Printf("%sCannot write to %s (ownership or permissions).%s\n", utils.Red, base, utils.Reset)
		return false
	}
	repoPath := toolLocalRepoPath(spec.Key)
	if dirExists(repoPath) {
		return true
	}
	gitPath, err := resolveToolPath("git")
	if err != nil {
		fmt.Printf("%sGit is not available.%s\n", utils.Red, utils.Reset)
		return false
	}
	cmd := exec.Command(gitPath, "clone", "--depth=1", spec.RepoURL, repoPath)
	return runTrackedSetupCommand("clone "+spec.DisplayName, cmd)
}

func setupLocalPythonTool(spec localToolSpec) bool {
	repoPath := toolLocalRepoPath(spec.Key)
	if !dirExists(repoPath) {
		fmt.Printf("%sLocal repository not found: %s%s\n", utils.Red, repoPath, utils.Reset)
		return false
	}
	if !isDirWritable(repoPath) {
		fmt.Printf("%sCannot write inside %s (fix ownership; avoid cloning OSINT tools as root).%s\n", utils.Red, repoPath, utils.Reset)
		return false
	}

	systemPythonPath, err := resolveSystemPythonPath()
	if err != nil {
		fmt.Printf("%sPython interpreter not found: %v%s\n", utils.Red, err, utils.Reset)
		return false
	}

	venvPath := filepath.Join(repoPath, ".venv")
	pythonPath, pipPath := venvPaths(venvPath)
	if !fileExists(pythonPath) {
		createCmd := exec.Command(systemPythonPath, "-m", "venv", venvPath)
		createCmd.Dir = repoPath
		if !runTrackedSetupCommand("venv "+spec.DisplayName, createCmd) {
			return false
		}
	}

	args := append([]string{}, localToolPipInstallArgs(spec.Key)...)
	installCmd := exec.Command(pipPath, args...)
	installCmd.Dir = repoPath
	return runTrackedSetupCommand("install "+spec.DisplayName, installCmd)
}

func localToolPipInstallArgs(tool string) []string {
	switch normalizeToolKey(tool) {
	case "recon-ng":
		return []string{"install", "-r", "REQUIREMENTS"}
	case "spiderfoot":
		return []string{"install", "-r", "requirements.txt"}
	default:
		return []string{"install", "."}
	}
}

func ensurePythonPackageToolReady(reader *bufio.Reader, commandName, pipPackage string) bool {
	if isToolInstalled(commandName) {
		return true
	}
	fmt.Printf("%s%s is not installed or not on PATH.%s\n", utils.Yellow, commandName, utils.Reset)
	if !promptYesNo(reader, "Install "+pipPackage+" with python -m pip --user now?") {
		return false
	}
	if !ensureDependencyRequirements(reader, []string{"python3|python|py", "pip3|pip"}) {
		return false
	}
	pythonPath, err := resolveSystemPythonPath()
	if err != nil {
		fmt.Printf("%sPython interpreter not found: %v%s\n", utils.Red, err, utils.Reset)
		return false
	}
	cmd := exec.Command(pythonPath, "-m", "pip", "install", "--user", pipPackage)
	if !runTrackedSetupCommand("pip install "+pipPackage, cmd) {
		return false
	}
	if !isToolInstalled(commandName) {
		fmt.Printf("%s%s installed, but the executable is still not visible on PATH.%s\n", utils.Yellow, commandName, utils.Reset)
		fmt.Printf("%sCheck that your user scripts directory is on PATH.%s\n", utils.Yellow, utils.Reset)
		return false
	}
	return true
}

func ensureSubdomainToolReady(reader *bufio.Reader) bool {
	if isToolInstalled("subfinder") || isToolInstalled("assetfinder") || isToolInstalled("amass") {
		return true
	}
	fmt.Printf("%sNo supported subdomain tool found (subfinder/assetfinder/amass).%s\n", utils.Yellow, utils.Reset)
	if !promptYesNo(reader, "Install subfinder with go install now?") {
		printDependencyInstallHints([]string{"subfinder"})
		return false
	}
	if !ensureDependencyRequirements(reader, []string{"go"}) {
		return false
	}
	goPath, err := resolveToolPath("go")
	if err != nil {
		fmt.Printf("%sGo executable not found.%s\n", utils.Red, utils.Reset)
		return false
	}
	cmd := exec.Command(goPath, "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
	if !runTrackedSetupCommand("go install subfinder", cmd) {
		return false
	}
	return isToolInstalled("subfinder")
}

func setupRecommendedLocalTools(reader *bufio.Reader) {
	for _, spec := range localOSINTToolSpecs() {
		fmt.Printf("\n%s=== %s ===%s\n", utils.Blue, spec.DisplayName, utils.Reset)
		_ = ensureLocalOrGlobalToolReady(reader, spec.Key)
	}
}

func printOSINTToolStatus() {
	fmt.Printf("%sTool directory:%s %s\n\n", utils.Green, utils.Reset, pathExecTools())
	for _, spec := range localOSINTToolSpecs() {
		repoPath := toolLocalRepoPath(spec.Key)
		status := "missing"
		switch {
		case isToolInstalled(spec.CommandName) || isToolInstalled(spec.Key):
			status = "global"
		case localPythonToolReady(spec.Key):
			status = "local .venv ready"
		case dirExists(repoPath):
			status = "repo downloaded, setup needed"
		}
		fmt.Printf("%s- %-13s%s %s\n", utils.Green, spec.DisplayName+":", utils.Reset, status)
	}

	for _, cli := range []string{"sherlock", "shodan", "subfinder", "assetfinder", "amass"} {
		status := "missing"
		if isToolInstalled(cli) {
			status = "available"
		}
		fmt.Printf("%s- %-13s%s %s\n", utils.Green, cli+":", utils.Reset, status)
	}
}

func promptYesNo(reader *bufio.Reader, question string) bool {
	fmt.Printf("%s%s (y/N): %s", utils.Yellow, question, utils.Reset)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "y" || answer == "yes"
}

func runTrackedSetupCommand(label string, cmd *exec.Cmd) bool {
	start := time.Now()
	fmt.Printf("%sRunning setup:%s %s\n", utils.Blue, utils.Reset, label)
	output, err := runSetupCommand(cmd)
	status := "ok"
	summary := "Setup command completed."
	if err != nil {
		status = "warning"
		summary = fmt.Sprintf("Setup command failed: %v", err)
		fmt.Printf("%s%s%s\n", utils.Yellow, summary, utils.Reset)
	}

	outFile := ""
	if len(output) > 0 {
		var saveErr error
		outFile, saveErr = saveOSINTOutput("osint-setup", label, output)
		if saveErr != nil {
			fmt.Printf("%sFailed to save setup output: %v%s\n", utils.Red, saveErr, utils.Reset)
		}
	}

	recordOSINT(OSINTRecord{
		Tool:            "osint-setup",
		Target:          label,
		Status:          status,
		Summary:         summary,
		OutputFile:      outFile,
		DurationSeconds: time.Since(start).Seconds(),
		RanAt:           time.Now(),
	})

	if err == nil {
		fmt.Printf("%sSetup completed: %s%s\n", utils.Green, label, utils.Reset)
	}
	return err == nil
}

func ensureShodanCLIConfigured() {
	key := strings.TrimSpace(os.Getenv("SHODAN_API_KEY"))
	if key == "" {
		return
	}
	if !isToolInstalled("shodan") {
		return
	}
	_, _ = runWithSystemShell("shodan init " + shellEscape(key))
}

func shellEscape(v string) string {
	if runtime.GOOS == "windows" {
		v = strings.ReplaceAll(v, `"`, `\"`)
		return `"` + v + `"`
	}
	v = strings.ReplaceAll(v, `'`, `'\''`)
	return "'" + v + "'"
}

func missingTools(requirements []string) []string {
	var missing []string
	for _, req := range requirements {
		if strings.Contains(req, "|") {
			options := strings.Split(req, "|")
			found := false
			for _, tool := range options {
				if isToolInstalled(strings.TrimSpace(tool)) {
					found = true
					break
				}
			}
			if !found {
				missing = append(missing, req)
			}
			continue
		}
		if !isToolInstalled(req) {
			missing = append(missing, req)
		}
	}
	return missing
}

func formatRequirementLabels(requirements []string) []string {
	labels := make([]string, 0, len(requirements))
	for _, req := range requirements {
		labels = append(labels, strings.ReplaceAll(strings.TrimSpace(req), "|", "/"))
	}
	return labels
}

func buildDependencyInstallCommands(requirements []string) []string {
	seen := map[string]struct{}{}
	var commands []string
	for _, req := range requirements {
		for _, cmd := range dependencyInstallCommandsForRequirement(req) {
			cmd = strings.TrimSpace(cmd)
			if cmd == "" {
				continue
			}
			if _, ok := seen[cmd]; ok {
				continue
			}
			seen[cmd] = struct{}{}
			commands = append(commands, cmd)
		}
	}
	return commands
}

func runDependencyInstallCommands(commands []string) {
	if len(commands) == 0 {
		return
	}

	fmt.Printf("\n%s=== OSINT DEPENDENCY SETUP ===%s\n", utils.Blue, utils.Reset)
	for _, cmd := range commands {
		fmt.Printf("%sRunning:%s %s\n", utils.Blue, utils.Reset, cmd)
		start := time.Now()
		out, err := runWithSystemShell(cmd)
		status := "ok"
		summary := "Dependency command completed."
		if err != nil {
			status = "warning"
			summary = fmt.Sprintf("Command failed: %v", err)
			fmt.Printf("%s%s%s\n", utils.Yellow, summary, utils.Reset)
		}

		outFile := ""
		if len(out) > 0 {
			var saveErr error
			outFile, saveErr = saveOSINTOutput("osint-setup", runtime.GOOS, out)
			if saveErr != nil {
				fmt.Printf("%sFailed to save setup output: %v%s\n", utils.Red, saveErr, utils.Reset)
			}
		}

		recordOSINT(OSINTRecord{
			Tool:            "osint-setup",
			Target:          runtime.GOOS,
			Status:          status,
			Summary:         summary + " cmd=" + cmd,
			OutputFile:      outFile,
			DurationSeconds: time.Since(start).Seconds(),
			RanAt:           time.Now(),
		})
	}
	fmt.Printf("%sDependency setup finished.%s\n\n", utils.Green, utils.Reset)
}

func printDependencyInstallHints(requirements []string) {
	if len(requirements) == 0 {
		return
	}
	fmt.Printf("%sInstall these dependencies manually:%s\n", utils.Yellow, utils.Reset)
	for _, req := range requirements {
		fmt.Printf("%s- %s%s\n", utils.Yellow, dependencyInstallHint(req), utils.Reset)
	}
}

func dependencyInstallHint(requirement string) string {
	switch normalizeRequirementKey(requirement) {
	case "whois":
		return "whois: install the 'whois' package with your package manager."
	case "dns":
		return "dig/nslookup: install dnsutils (Debian/Ubuntu), bind (Arch/macOS) or the equivalent package for your OS."
	case "python":
		return "python3: install Python 3 with your package manager."
	case "pip":
		return "pip3: install Python pip (for example 'python3-pip' on Debian/Ubuntu)."
	case "git":
		return "git: install Git with your package manager."
	case "go":
		return "go: install Go with your package manager."
	default:
		return strings.ReplaceAll(strings.TrimSpace(requirement), "|", "/")
	}
}

func dependencyInstallCommandsForRequirement(requirement string) []string {
	manager := detectPackageManager()
	key := normalizeRequirementKey(requirement)

	switch manager {
	case "apt":
		switch key {
		case "whois":
			return []string{"sudo apt-get install -y whois"}
		case "dns":
			return []string{"sudo apt-get install -y dnsutils"}
		case "python":
			return []string{"sudo apt-get install -y python3"}
		case "pip":
			return []string{"sudo apt-get install -y python3-pip"}
		case "git":
			return []string{"sudo apt-get install -y git"}
		case "go":
			return []string{"sudo apt-get install -y golang-go"}
		}
	case "pacman":
		switch key {
		case "whois":
			return []string{"sudo pacman -S --noconfirm whois"}
		case "dns":
			return []string{"sudo pacman -S --noconfirm bind"}
		case "python":
			return []string{"sudo pacman -S --noconfirm python"}
		case "pip":
			return []string{"sudo pacman -S --noconfirm python-pip"}
		case "git":
			return []string{"sudo pacman -S --noconfirm git"}
		case "go":
			return []string{"sudo pacman -S --noconfirm go"}
		}
	case "dnf":
		switch key {
		case "whois":
			return []string{"sudo dnf install -y whois"}
		case "dns":
			return []string{"sudo dnf install -y bind-utils"}
		case "python":
			return []string{"sudo dnf install -y python3"}
		case "pip":
			return []string{"sudo dnf install -y python3-pip"}
		case "git":
			return []string{"sudo dnf install -y git"}
		case "go":
			return []string{"sudo dnf install -y golang"}
		}
	case "brew":
		switch key {
		case "whois":
			return []string{"brew install whois"}
		case "dns":
			return []string{"brew install bind"}
		case "python", "pip":
			return []string{"brew install python"}
		case "git":
			return []string{"brew install git"}
		case "go":
			return []string{"brew install go"}
		}
	case "winget":
		switch key {
		case "python":
			return []string{`winget install --id Python.Python.3 --accept-package-agreements --accept-source-agreements`}
		case "pip":
			return []string{`py -m ensurepip --upgrade || python -m ensurepip --upgrade`}
		case "git":
			return []string{`winget install --id Git.Git --accept-package-agreements --accept-source-agreements`}
		case "go":
			return []string{`winget install --id GoLang.Go --accept-package-agreements --accept-source-agreements`}
		}
	case "choco":
		switch key {
		case "python":
			return []string{`choco install -y python`}
		case "pip":
			return []string{`py -m ensurepip --upgrade || python -m ensurepip --upgrade`}
		case "git":
			return []string{`choco install -y git`}
		case "go":
			return []string{`choco install -y golang`}
		}
	}

	return nil
}

func detectPackageManager() string {
	switch {
	case runtime.GOOS == "linux" && isToolInstalled("apt-get"):
		return "apt"
	case runtime.GOOS == "linux" && isToolInstalled("pacman"):
		return "pacman"
	case runtime.GOOS == "linux" && isToolInstalled("dnf"):
		return "dnf"
	case runtime.GOOS == "darwin" && isToolInstalled("brew"):
		return "brew"
	case runtime.GOOS == "windows" && isToolInstalled("winget"):
		return "winget"
	case runtime.GOOS == "windows" && isToolInstalled("choco"):
		return "choco"
	default:
		return ""
	}
}

func normalizeRequirementKey(requirement string) string {
	switch strings.ToLower(strings.TrimSpace(requirement)) {
	case "dig|nslookup":
		return "dns"
	case "python3|python|py":
		return "python"
	case "pip3|pip":
		return "pip"
	case "git":
		return "git"
	case "go":
		return "go"
	default:
		return strings.ToLower(strings.TrimSpace(requirement))
	}
}

func ViewOSINTStats() {
	utils.ClearTerminal()
	fmt.Printf("\n%s=== OSINT STATISTICS ===%s\n\n", utils.Blue, utils.Reset)

	history, err := loadOSINTHistory()
	if err != nil {
		fmt.Printf("%sNo OSINT data found.%s\n", utils.Red, utils.Reset)
		return
	}
	lookupHistory := filterLookupHistory(history)
	if len(lookupHistory.Records) == 0 {
		fmt.Printf("%sNo OSINT records available.%s\n", utils.Yellow, utils.Reset)
		return
	}

	stats := buildOSINTStats(lookupHistory)
	fmt.Printf("%sTotal Runs:%s %d\n", utils.Green, utils.Reset, stats.TotalRuns)
	fmt.Printf("%sSuccess:%s %d\n", utils.Green, utils.Reset, stats.SuccessRuns)
	fmt.Printf("%sWarnings:%s %d\n", utils.Yellow, utils.Reset, stats.WarningRuns)
	fmt.Printf("%sErrors:%s %d\n", utils.Red, utils.Reset, stats.ErrorRuns)
	fmt.Printf("%sUnique Tools:%s %d\n", utils.Green, utils.Reset, stats.UniqueTools)
	fmt.Printf("%sUnique Targets:%s %d\n", utils.Green, utils.Reset, stats.UniqueTargets)
	fmt.Printf("%sAverage Duration:%s %.2fs\n", utils.Green, utils.Reset, stats.AverageDuration)
	fmt.Printf("%sLast Run:%s %s\n", utils.Green, utils.Reset, stats.LastRun.Format("2006-01-02 15:04:05"))
	fmt.Printf("%sTop Tools:%s %s\n", utils.Blue, utils.Reset, strings.Join(stats.TopTools, ", "))
	fmt.Printf("%sTop Targets:%s %s\n\n", utils.Blue, utils.Reset, strings.Join(stats.TopTargets, ", "))

	printOSINTHistoryList(lookupHistory)

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%sOptions:%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s[1] View record output%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s[2] Delete all OSINT history/reports%s\n", utils.Red, utils.Reset)
	fmt.Printf("%s[3] Return%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("\n%sChoose option: %s", utils.Green, utils.Reset)
	menuChoice, _ := reader.ReadString('\n')
	menuChoice = strings.TrimSpace(menuChoice)

	switch menuChoice {
	case "2":
		deleteAllOSINTData()
		return
	case "3":
		return
	}

	fmt.Printf("%sChoose record number to show output (Enter = latest): %s", utils.Green, utils.Reset)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	selected := len(lookupHistory.Records) - 1
	if input != "" {
		idx, convErr := strconv.Atoi(input)
		if convErr != nil || idx < 1 || idx > len(lookupHistory.Records) {
			fmt.Printf("%sInvalid selection. Showing latest.%s\n", utils.Yellow, utils.Reset)
		} else {
			selected = idx - 1
		}
	}

	rec := lookupHistory.Records[selected]
	fmt.Printf("\n%s=== SELECTED RECORD ===%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%sTool:%s %s\n", utils.Green, utils.Reset, rec.Tool)
	fmt.Printf("%sTarget:%s %s\n", utils.Green, utils.Reset, rec.Target)
	fmt.Printf("%sStatus:%s %s\n", utils.Green, utils.Reset, rec.Status)
	fmt.Printf("%sTime:%s %s\n", utils.Green, utils.Reset, rec.RanAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("%sSummary:%s %s\n", utils.Green, utils.Reset, rec.Summary)
	if rec.OutputFile != "" {
		fmt.Printf("%sOutput File:%s %s\n\n", utils.Green, utils.Reset, rec.OutputFile)
		showOSINTOutputFromFile(reader, rec.OutputFile)
	} else {
		fmt.Printf("%sNo output file for this record.%s\n", utils.Yellow, utils.Reset)
	}
}

func buildOSINTStats(history *OSINTHistory) OSINTStats {
	stats := OSINTStats{
		TotalRuns: len(history.Records),
	}
	toolCounts := map[string]int{}
	targetCounts := map[string]int{}
	toolSet := map[string]struct{}{}
	targetSet := map[string]struct{}{}
	var durationSum float64

	for _, r := range history.Records {
		switch r.Status {
		case "ok":
			stats.SuccessRuns++
		case "warning":
			stats.WarningRuns++
		case "error":
			stats.ErrorRuns++
		}

		if r.RanAt.After(stats.LastRun) {
			stats.LastRun = r.RanAt
		}
		durationSum += r.DurationSeconds
		toolCounts[r.Tool]++
		targetCounts[r.Target]++
		toolSet[r.Tool] = struct{}{}
		targetSet[r.Target] = struct{}{}
	}

	stats.UniqueTools = len(toolSet)
	stats.UniqueTargets = len(targetSet)
	stats.AverageDuration = durationSum / float64(stats.TotalRuns)
	stats.TopTools = topCounts(toolCounts, 5)
	stats.TopTargets = topCounts(targetCounts, 5)
	return stats
}

func filterLookupHistory(history *OSINTHistory) *OSINTHistory {
	filtered := &OSINTHistory{Records: make([]OSINTRecord, 0, len(history.Records))}
	for _, rec := range history.Records {
		if isSetupRecord(rec.Tool) {
			continue
		}
		filtered.Records = append(filtered.Records, rec)
	}
	return filtered
}

func isSetupRecord(tool string) bool {
	tool = strings.ToLower(strings.TrimSpace(tool))
	return strings.HasPrefix(tool, "osint-setup")
}

func topCounts(counts map[string]int, n int) []string {
	type entry struct {
		Key   string
		Count int
	}
	entries := make([]entry, 0, len(counts))
	for k, c := range counts {
		entries = append(entries, entry{Key: k, Count: c})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count == entries[j].Count {
			return entries[i].Key < entries[j].Key
		}
		return entries[i].Count > entries[j].Count
	})
	if len(entries) == 0 {
		return []string{"N/A"}
	}
	if n > len(entries) {
		n = len(entries)
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("%s(%d)", entries[i].Key, entries[i].Count))
	}
	return out
}

func loadOSINTHistory() (*OSINTHistory, error) {
	data, err := os.ReadFile(pathOSINTResults())
	if err != nil {
		return nil, err
	}

	var history OSINTHistory
	if err := json.Unmarshal(data, &history); err != nil {
		return nil, err
	}
	return &history, nil
}

func printOSINTHistoryList(history *OSINTHistory) {
	fmt.Printf("%s=== HISTORY ===%s\n", utils.Blue, utils.Reset)
	for i, rec := range history.Records {
		color := utils.Green
		if rec.Status == "warning" {
			color = utils.Yellow
		}
		if rec.Status == "error" {
			color = utils.Red
		}
		fmt.Printf("%s[%d]%s %s | %s | %s | %.2fs\n",
			color, i+1, utils.Reset, rec.RanAt.Format("2006-01-02 15:04:05"), rec.Tool, rec.Target, rec.DurationSeconds)
	}
	fmt.Println()
}

func showOSINTOutputFromFile(reader *bufio.Reader, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("%sCould not read output file: %v%s\n", utils.Red, err, utils.Reset)
		return
	}

	content := strings.ReplaceAll(string(data), "\r\n", "\n")
	if looksLikeHTML(content) {
		title := extractHTMLTitle(content)
		plain := normalizeWhitespace(stripHTMLTags(content))
		if plain == "" {
			plain = "No readable text extracted from HTML content."
		}
		var sanitized strings.Builder
		sanitized.WriteString("HTML content detected in file. Rendering parsed text only.\n")
		if title != "" {
			sanitized.WriteString("Title: " + title + "\n\n")
		}
		sanitized.WriteString(plain)
		content = sanitized.String()
	}

	lines := strings.Split(content, "\n")
	if len(lines) == 0 {
		fmt.Printf("%sOutput file is empty.%s\n", utils.Yellow, utils.Reset)
		return
	}

	const pageSize = 40
	totalPages := (len(lines) + pageSize - 1) / pageSize
	page := 0

	for {
		start := page * pageSize
		end := start + pageSize
		if end > len(lines) {
			end = len(lines)
		}

		utils.ClearTerminal()
		fmt.Printf("%s=== OUTPUT VIEWER ===%s\n", utils.Blue, utils.Reset)
		fmt.Printf("%sFile:%s %s\n", utils.Green, utils.Reset, path)
		fmt.Printf("%sPage:%s %d/%d | lines %d-%d of %d\n\n", utils.Green, utils.Reset, page+1, totalPages, start+1, end, len(lines))
		fmt.Println(strings.Join(lines[start:end], "\n"))
		fmt.Printf("\n%sControls:%s [n] next  [p] prev  [q] quit\n", utils.Yellow, utils.Reset)
		fmt.Printf("%sChoice: %s", utils.Green, utils.Reset)

		cmd, _ := reader.ReadString('\n')
		cmd = strings.ToLower(strings.TrimSpace(cmd))
		switch cmd {
		case "n":
			if page < totalPages-1 {
				page++
			}
		case "p":
			if page > 0 {
				page--
			}
		case "q", "":
			return
		default:

		}
	}
}

func printOSINTOutputPreview(tool string, output []byte) {
	content := string(output)
	if looksLikeHTML(content) {
		title := extractHTMLTitle(content)
		plain := normalizeWhitespace(stripHTMLTags(content))
		if len(plain) > 1200 {
			plain = plain[:1200]
		}

		fmt.Printf("\n%s=== OUTPUT PREVIEW ===%s\n", utils.Blue, utils.Reset)
		fmt.Printf("%sWeb content detected for %s. Showing parsed summary (not raw HTML).%s\n", utils.Yellow, tool, utils.Reset)
		if title != "" {
			fmt.Printf("%sTitle:%s %s\n", utils.Green, utils.Reset, title)
		}
		if plain == "" {
			fmt.Printf("%sNo readable text extracted from HTML. Full output is saved to file.%s\n\n", utils.Yellow, utils.Reset)
		} else {
			fmt.Printf("%sSnippet:%s %s\n\n", utils.Green, utils.Reset, plain)
		}
		return
	}

	fmt.Printf("\n%s=== OUTPUT PREVIEW ===%s\n", utils.Blue, utils.Reset)
	lines := strings.Split(content, "\n")
	maxLines := 40
	if len(lines) > maxLines {
		lines = lines[:maxLines]
		fmt.Printf("%sShowing first %d lines. Full output saved to file.%s\n", utils.Yellow, maxLines, utils.Reset)
	}
	fmt.Println(strings.Join(lines, "\n"))
	fmt.Println()
}

func deleteAllOSINTData() {
	if err := os.Remove(pathOSINTResults()); err != nil && !os.IsNotExist(err) {
		fmt.Printf("%sFailed to delete %s: %v%s\n", utils.Red, pathOSINTResults(), err, utils.Reset)
		return
	}
	if err := os.RemoveAll(pathOSINTReports()); err != nil && !os.IsNotExist(err) {
		fmt.Printf("%sFailed to delete %s: %v%s\n", utils.Red, pathOSINTReports(), err, utils.Reset)
		return
	}
	if err := os.MkdirAll(pathOSINTReports(), 0755); err != nil {
		fmt.Printf("%sFailed to recreate reports directory: %v%s\n", utils.Red, err, utils.Reset)
		return
	}
	fmt.Printf("%sOSINT history and reports deleted successfully.%s\n", utils.Green, utils.Reset)
}

func extractActionableOutput(tool string, output []byte) []byte {
	text := strings.ReplaceAll(string(output), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	tool = strings.ToLower(strings.TrimSpace(tool))

	var keep []string
	for _, line := range lines {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		ll := strings.ToLower(l)

		if strings.Contains(ll, "checking") || strings.Contains(ll, "trying") || strings.Contains(ll, "scanning") {
			continue
		}
		if strings.HasPrefix(ll, "[*]") || strings.HasPrefix(ll, "[i]") {
			continue
		}
		if strings.Contains(ll, "not found") || strings.Contains(ll, "error while") {
			continue
		}

		switch tool {
		case "sherlock":

			if strings.Contains(l, "http://") || strings.Contains(l, "https://") || strings.Contains(ll, "[+]") {
				keep = append(keep, l)
			}
		case "whois":
			if hasAnyPrefixCI(l, []string{"Domain Name:", "Registrar:", "Creation Date:", "Registry Expiry Date:", "Name Server:", "Org:", "Country:", "Admin Email:"}) {
				keep = append(keep, l)
			}
		case "dns-a", "dns-aaaa", "dns-mx", "dns-txt", "dns-ns":
			keep = append(keep, l)
		case "subfinder", "assetfinder", "amass":
			if isLikelyDomain(l) {
				keep = append(keep, l)
			}
		default:
			keep = append(keep, l)
		}
	}

	keep = dedupeKeepOrder(keep)
	if len(keep) == 0 {
		return []byte{}
	}
	result := strings.Join(keep, "\n") + "\n"

	switch tool {
	case "dns-a":
		return []byte(formatDNSResult("A (IPv4)", "Maps domain to IPv4 addresses used by the service.", keep))
	case "dns-aaaa":
		return []byte(formatDNSResult("AAAA (IPv6)", "Maps domain to IPv6 addresses used by the service.", keep))
	case "dns-mx":
		return []byte(formatDNSResult("MX (Mail Servers)", "Shows mail servers that receive email for this domain.", keep))
	case "dns-txt":
		return []byte(formatDNSResult("TXT (Text Records)", "Commonly includes SPF/verification/security metadata.", keep))
	case "dns-ns":
		return []byte(formatDNSResult("NS (Name Servers)", "Shows DNS providers/authoritative name servers.", keep))
	case "theharvester":
		return []byte(formatTheHarvesterResult(keep))
	default:
		return []byte(result)
	}
}

func hasAnyPrefixCI(s string, prefixes []string) bool {
	sl := strings.ToLower(s)
	for _, p := range prefixes {
		if strings.HasPrefix(sl, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func dedupeKeepOrder(lines []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if _, ok := seen[l]; ok {
			continue
		}
		seen[l] = struct{}{}
		out = append(out, l)
	}
	return out
}

func shouldAttemptPkgResourcesFix(cmdName string, output []byte) bool {
	if strings.ToLower(strings.TrimSpace(cmdName)) != "shodan" {
		return false
	}
	msg := strings.ToLower(string(output))
	return strings.Contains(msg, "module not found") && strings.Contains(msg, "pkg_resources")
}

func formatDNSResult(recordType, meaning string, values []string) string {
	var b strings.Builder
	b.WriteString("DNS RESULT SUMMARY\n")
	b.WriteString("Record Type: " + recordType + "\n")
	b.WriteString("What this means: " + meaning + "\n")
	b.WriteString("Total records found: " + strconv.Itoa(len(values)) + "\n\n")
	b.WriteString("Records:\n")
	for i, v := range values {
		b.WriteString(fmt.Sprintf("%d. %s\n", i+1, v))
	}
	return b.String()
}

func formatTheHarvesterResult(lines []string) string {
	emailRe := regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)
	ipRe := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

	var domains []string
	var emails []string
	var ips []string

	for _, l := range lines {
		for _, e := range emailRe.FindAllString(l, -1) {
			emails = append(emails, strings.ToLower(strings.TrimSpace(e)))
		}
		for _, ip := range ipRe.FindAllString(l, -1) {
			ips = append(ips, strings.TrimSpace(ip))
		}
		if isLikelyDomain(strings.TrimSpace(l)) {
			domains = append(domains, strings.TrimSpace(l))
		}
	}

	domains = dedupeKeepOrder(domains)
	emails = dedupeKeepOrder(emails)
	ips = dedupeKeepOrder(ips)

	var b strings.Builder
	b.WriteString("THEHARVESTER RESULT SUMMARY\n")
	b.WriteString("What this means: discovered public footprint linked to the target domain.\n")
	b.WriteString(fmt.Sprintf("Subdomains found: %d | Emails found: %d | IPs found: %d\n\n", len(domains), len(emails), len(ips)))

	b.WriteString("Subdomains:\n")
	if len(domains) == 0 {
		b.WriteString("- None detected\n")
	} else {
		for i, d := range domains {
			b.WriteString(fmt.Sprintf("%d. %s\n", i+1, d))
		}
	}

	b.WriteString("\nEmails:\n")
	if len(emails) == 0 {
		b.WriteString("- None detected\n")
	} else {
		for i, e := range emails {
			b.WriteString(fmt.Sprintf("%d. %s\n", i+1, e))
		}
	}

	b.WriteString("\nIP Addresses:\n")
	if len(ips) == 0 {
		b.WriteString("- None detected\n")
	} else {
		for i, ip := range ips {
			b.WriteString(fmt.Sprintf("%d. %s\n", i+1, ip))
		}
	}

	return b.String()
}

func looksLikeHTML(content string) bool {
	lc := strings.ToLower(content)
	return strings.Contains(lc, "<html") || strings.Contains(lc, "<!doctype html") || strings.Contains(lc, "</body>")
}

func extractHTMLTitle(content string) string {
	re := regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	match := re.FindStringSubmatch(content)
	if len(match) < 2 {
		return ""
	}
	return normalizeWhitespace(stripHTMLTags(match[1]))
}

func stripHTMLTags(content string) string {
	content = removeHTMLNoiseBlocks(content)
	re := regexp.MustCompile(`(?is)<[^>]+>`)
	plain := re.ReplaceAllString(content, " ")
	replacer := strings.NewReplacer(
		"&nbsp;", " ",
		"&amp;", "&",
		"&lt;", "<",
		"&gt;", ">",
		"&quot;", "\"",
		"&#39;", "'",
	)
	return replacer.Replace(plain)
}

func normalizeWhitespace(content string) string {
	return strings.Join(strings.Fields(content), " ")
}

func removeHTMLNoiseBlocks(content string) string {
	blockPatterns := []string{
		`(?is)<script[^>]*>.*?</script>`,
		`(?is)<style[^>]*>.*?</style>`,
		`(?is)<noscript[^>]*>.*?</noscript>`,
		`(?is)<svg[^>]*>.*?</svg>`,
		`(?is)<template[^>]*>.*?</template>`,
	}
	clean := content
	for _, p := range blockPatterns {
		re := regexp.MustCompile(p)
		clean = re.ReplaceAllString(clean, " ")
	}
	return clean
}

func extractReadableTextFromHTML(content string) string {
	plain := normalizeWhitespace(stripHTMLTags(content))

	noise := []string{"self.__next_f", "window.__", "__NEXT_DATA__", "@keyframes", "function(", "=>"}
	for _, n := range noise {
		if strings.Contains(strings.ToLower(plain), strings.ToLower(n)) {
			plain = strings.ReplaceAll(plain, n, " ")
		}
	}
	return normalizeWhitespace(plain)
}

func resolveFileExecutablePath(p string) (string, error) {
	info, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", errors.New("is directory")
	}
	if runtime.GOOS != "windows" && info.Mode().IsRegular() {
		if info.Mode().Perm()&0111 == 0 {
			return "", errors.New("not executable")
		}
	}
	return filepath.Clean(p), nil
}

func resolveToolPath(name string) (string, error) {
	for _, candidateName := range toolNameCandidates(name) {
		if strings.ContainsRune(candidateName, os.PathSeparator) {
			if p, err := resolveFileExecutablePath(candidateName); err == nil {
				return p, nil
			}
		}

		if p, err := exec.LookPath(candidateName); err == nil {
			return p, nil
		}

		for _, dir := range commonToolSearchDirs() {
			candidate := filepath.Join(dir, candidateName)
			if runtime.GOOS == "windows" {
				winCandidates := []string{candidate}
				for _, ext := range []string{".exe", ".cmd", ".bat", ".ps1"} {
					winCandidates = append(winCandidates, candidate+ext)
				}
				for _, c := range winCandidates {
					if p, err := resolveFileExecutablePath(c); err == nil {
						return p, nil
					}
				}
				continue
			}
			if p, err := resolveFileExecutablePath(candidate); err == nil {
				return p, nil
			}
		}
	}

	return "", errors.New("not found")
}

func commonToolSearchDirs() []string {
	home, _ := os.UserHomeDir()
	dirs := []string{
		filepath.Join(home, ".local", "bin"),
		filepath.Join(home, "go", "bin"),
		"/usr/local/bin",
		"/usr/bin",
		"/bin",
		"/opt/homebrew/bin",
		"/snap/bin",
	}
	dirs = append(dirs, localExecToolSearchDirs()...)
	dirs = append(dirs, discoverPipxVenvBinDirs(home)...)
	if runtime.GOOS == "windows" {
		appData := os.Getenv("APPDATA")
		localAppData := os.Getenv("LOCALAPPDATA")
		userProfile := os.Getenv("USERPROFILE")
		dirs = append(dirs,
			filepath.Join(home, "go", "bin"),
			filepath.Join(userProfile, "go", "bin"),
			filepath.Join(appData, "Python"),
			filepath.Join(localAppData, "Programs", "Python"),
			filepath.Join(localAppData, "Microsoft", "WindowsApps"),
			filepath.Join("C:", "Program Files", "Git", "cmd"),
			filepath.Join("C:", "Program Files", "Nmap"),
		)
		dirs = append(dirs, discoverWindowsPythonScriptDirs(home, appData, localAppData)...)
	}

	pathEntries := filepath.SplitList(os.Getenv("PATH"))
	seen := map[string]struct{}{}
	merged := make([]string, 0, len(dirs)+len(pathEntries))

	for _, d := range append(dirs, pathEntries...) {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		merged = append(merged, d)
	}
	return merged
}

func localExecToolSearchDirs() []string {
	var dirs []string
	for _, spec := range localOSINTToolSpecs() {
		repoPath := toolLocalRepoPath(spec.Key)
		if repoPath == "" {
			continue
		}
		if runtime.GOOS == "windows" {
			dirs = append(dirs,
				filepath.Join(repoPath, ".venv", "Scripts"),
				filepath.Join(repoPath, "bin"),
				repoPath,
			)
			continue
		}
		dirs = append(dirs,
			filepath.Join(repoPath, ".venv", "bin"),
			filepath.Join(repoPath, "bin"),
			repoPath,
		)
	}
	return dirs
}

func processEnvWithExpandedPath() []string {
	env := os.Environ()
	newPath := strings.Join(commonToolSearchDirs(), string(os.PathListSeparator))
	hasPath := false
	for i, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			env[i] = "PATH=" + newPath
			hasPath = true
			break
		}
	}
	if !hasPath {
		env = append(env, "PATH="+newPath)
	}
	return env
}

func runWithSystemShell(command string) ([]byte, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("bash", "-lc", command)
	}
	cmd.Env = processEnvWithExpandedPath()
	output, err, _ := runCommandCaptureWithProgressLive("shell: "+command, cmd, 15*time.Minute, true)
	return output, err
}

func discoverWindowsPythonScriptDirs(home, appData, localAppData string) []string {
	var dirs []string
	baseCandidates := []string{
		filepath.Join(home, "AppData", "Roaming", "Python"),
		filepath.Join(home, "AppData", "Local", "Programs", "Python"),
		filepath.Join(appData, "Python"),
		filepath.Join(localAppData, "Programs", "Python"),
	}

	for _, base := range baseCandidates {
		if strings.TrimSpace(base) == "" {
			continue
		}
		pattern := filepath.Join(base, "Python*", "Scripts")
		matches, _ := filepath.Glob(pattern)
		dirs = append(dirs, matches...)
	}
	return dirs
}

func discoverPipxVenvBinDirs(home string) []string {
	var dirs []string
	baseCandidates := []string{
		filepath.Join(home, ".local", "pipx", "venvs"),
		filepath.Join(home, ".pipx", "venvs"),
	}

	for _, base := range baseCandidates {
		if strings.TrimSpace(base) == "" {
			continue
		}
		pattern := filepath.Join(base, "*", "bin")
		matches, _ := filepath.Glob(pattern)
		dirs = append(dirs, matches...)
	}
	return dirs
}

func toolNameCandidates(name string) []string {
	base := strings.TrimSpace(name)
	if base == "" {
		return nil
	}
	candidates := []string{base}

	aliases := map[string][]string{
		"theharvester": {"theHarvester", "theharvester"},
		"theHarvester": {"theHarvester", "theharvester"},
		"recon-ng":     {"recon-ng", "recon-ng.py"},
		"sherlock":     {"sherlock", "sherlock.py"},
		"spiderfoot":   {"spiderfoot", "spiderfoot.py", "sf.py"},
	}

	if alt, ok := aliases[base]; ok {
		candidates = append(candidates, alt...)
	} else if alt, ok := aliases[strings.ToLower(base)]; ok {
		candidates = append(candidates, alt...)
	}

	return dedupeKeepOrder(candidates)
}

func isPythonModuleFallbackTool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "theharvester", "theharvester.py", "theHarvester", "maigret":
		return true
	default:
		return false
	}
}

func resolvePythonModuleCommand(tool string, toolArgs []string) (string, []string, error) {
	module := ""
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "theharvester", "theharvester.py", "theHarvester":
		module = "theHarvester"
	case "maigret":
		module = "maigret"
	default:
		return "", nil, errors.New("unsupported module fallback")
	}

	pythonCandidates := []string{"python3", "python", "py"}
	for _, py := range pythonCandidates {
		pyPath, err := resolveToolPath(py)
		if err != nil {
			continue
		}

		checkArgs := []string{"-c", "import importlib.util,sys;sys.exit(0 if importlib.util.find_spec('" + module + "') else 1)"}
		checkCmd := exec.Command(pyPath, checkArgs...)
		checkCmd.Env = processEnvWithExpandedPath()
		if checkErr := checkCmd.Run(); checkErr != nil {
			continue
		}

		args := append([]string{"-m", module}, toolArgs...)
		return pyPath, args, nil
	}

	return "", nil, errors.New("python module not available")
}

func manualRepairHintForTool(cmdName string) string {
	switch strings.ToLower(strings.TrimSpace(cmdName)) {
	case "shodan":
		return "python3 -m pip install --user setuptools"
	default:
		return ""
	}
}

func buildMissingToolMessage(tool string) string {
	key := normalizeToolKey(tool)
	if key == "subdomain-enum" {
		return strings.Join([]string{
			"No supported subdomain tool found.",
			"Install one of the following:",
			"subfinder: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
			"assetfinder: go install github.com/tomnomnom/assetfinder@latest",
			"amass: go install github.com/owasp-amass/amass/v4/...@master",
		}, "\n")
	}

	lines := []string{fmt.Sprintf("Tool '%s' is not installed.", toolDisplayName(tool))}
	if note := toolDependencyNote(tool); note != "" {
		lines = append(lines, note)
	}
	if install := toolInstallCommand(tool); install != "" {
		lines = append(lines, "Install: "+install)
	}
	if local := toolLocalInstallCommand(tool); local != "" {
		lines = append(lines, "Local/GitHub: "+local)
	}
	if run := toolLocalRunCommand(tool); run != "" {
		lines = append(lines, "Run local: "+run)
	}
	if key == "maigret" && dirExists(toolLocalRepoPath(tool)) {
		lines = append(lines, "Toolkit option: choose the temporary isolated env when prompted; it is removed after the run finishes.")
	}
	return strings.Join(lines, "\n")
}

func toolDisplayName(tool string) string {
	switch normalizeToolKey(tool) {
	case "theharvester":
		return "theHarvester"
	default:
		return strings.TrimSpace(tool)
	}
}

func toolDependencyNote(tool string) string {
	pep668 := ""
	if detectPackageManager() == "pacman" {
		pep668 = " On Arch/PEP 668, if pip3 says 'externally-managed-environment', use a project .venv."
	}

	switch normalizeToolKey(tool) {
	case "maigret":
		return "Needs Python 3.10+ and pip3." + pep668
	case "theharvester":
		return "Needs Python 3.12+ and pip3." + pep668
	case "shodan", "sherlock":
		return "Needs Python 3 and pip3." + pep668
	default:
		return ""
	}
}

func toolInstallCommand(tool string) string {
	switch normalizeToolKey(tool) {
	case "whois":
		return "install the 'whois' package with your system package manager"
	case "dig", "nslookup":
		return "install dnsutils (Debian/Ubuntu) or bind (Arch/macOS)"
	case "maigret":
		return "pip3 install maigret"
	case "theharvester":
		return "pip3 install theHarvester"
	case "shodan":
		return "pip3 install shodan"
	case "sherlock":
		return "pip3 install sherlock-project"
	default:
		return ""
	}
}

func toolLocalInstallCommand(tool string) string {
	repoPath := toolLocalRepoPath(tool)
	if repoPath != "" && dirExists(repoPath) {
		switch normalizeToolKey(tool) {
		case "maigret", "theharvester":
			return "cd " + repoPath + " && " + repoVenvCreateAndPipInstallCmd(".")
		case "recon-ng":
			return "cd " + repoPath + " && " + repoVenvCreateAndPipInstallCmd("-r REQUIREMENTS")
		case "spiderfoot":
			return "cd " + repoPath + " && " + repoVenvCreateAndPipInstallCmd("-r requirements.txt")
		}
	}

	switch normalizeToolKey(tool) {
	case "maigret":
		return "git clone https://github.com/soxoj/maigret && cd maigret && " + repoVenvCreateAndPipInstallCmd(".")
	case "theharvester":
		return "git clone https://github.com/laramies/theHarvester && cd theHarvester && " + repoVenvCreateAndPipInstallCmd(".")
	case "recon-ng":
		return "git clone https://github.com/lanmaster53/recon-ng && cd recon-ng && " + repoVenvCreateAndPipInstallCmd("-r REQUIREMENTS")
	case "spiderfoot":
		return "git clone https://github.com/smicallef/spiderfoot && cd spiderfoot && " + repoVenvCreateAndPipInstallCmd("-r requirements.txt")
	default:
		return ""
	}
}

func toolLocalRunCommand(tool string) string {
	repoPath := toolLocalRepoPath(tool)
	if repoPath == "" {
		repoPath = normalizeToolKey(tool)
	}

	pythonCmd := repoVenvPythonCmd(repoPath)
	switch normalizeToolKey(tool) {
	case "maigret":
		return "cd " + repoPath + " && " + pythonCmd + " -m maigret username --html"
	case "theharvester":
		return "cd " + repoPath + " && " + pythonCmd + " -m theHarvester -d example.com -b crtsh -l 500"
	case "recon-ng":
		return "cd " + repoPath + " && " + pythonCmd + " recon-ng -r script.rc"
	case "spiderfoot":
		return "cd " + repoPath + " && " + pythonCmd + " sf.py -s example.com -q"
	default:
		return ""
	}
}

func repoVenvCreateAndPipInstallCmd(installTarget string) string {
	pythonCmd, pipCmd := repoVenvPythonAndPipCmd()
	return pythonCmd + " -m venv .venv && " + pipCmd + " install " + installTarget
}

func repoVenvPythonAndPipCmd() (string, string) {
	if runtime.GOOS == "windows" {
		return `py`, `.venv\Scripts\pip.exe`
	}
	return "python3", ".venv/bin/pip"
}

func repoVenvPythonCmd(repoPath string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(repoPath, `.venv`, `Scripts`, `python.exe`)
	}
	return filepath.Join(repoPath, ".venv", "bin", "python")
}

func toolLocalRepoPath(tool string) string {
	switch normalizeToolKey(tool) {
	case "maigret":
		return filepath.Join(pathExecTools(), "maigret")
	case "theharvester":
		return filepath.Join(pathExecTools(), "theHarvester")
	case "recon-ng":
		return filepath.Join(pathExecTools(), "recon-ng")
	case "spiderfoot":
		return filepath.Join(pathExecTools(), "spiderfoot")
	default:
		return ""
	}
}

func normalizeToolKey(tool string) string {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "theharvester", "theharvester.py":
		return "theharvester"
	default:
		return strings.ToLower(strings.TrimSpace(tool))
	}
}

func runLocalPythonModuleCommand(toolName, target, repoPath, module string, args []string) bool {
	if !dirExists(repoPath) {
		return false
	}
	pythonPath, err := resolveRepoPythonPath(repoPath)
	if err != nil {
		return false
	}

	cmd := exec.Command(pythonPath, append([]string{"-m", module}, args...)...)
	if normalizeToolKey(toolName) == "maigret" {
		cmd.Dir = maigretOutputDir()
	} else {
		cmd.Dir = repoPath
	}
	executeOSINTCommand(toolName, target, module, cmd, time.Now())
	return true
}

func runTempRepoPythonModuleCommand(toolName, target, repoPath, module string, args []string) error {
	if !dirExists(repoPath) {
		return errors.New("local repository not found")
	}

	systemPythonPath, err := resolveSystemPythonPath()
	if err != nil {
		return err
	}

	tempDir, err := os.MkdirTemp("", "g0-"+normalizeToolKey(toolName)+"-")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
		fmt.Printf("%sTemporary %s environment removed.%s\n", utils.Blue, toolDisplayName(toolName), utils.Reset)
	}()

	venvPath := filepath.Join(tempDir, ".venv")
	pythonPath, pipPath := venvPaths(venvPath)

	fmt.Printf("%sPreparing temporary %s environment...%s\n", utils.Blue, toolDisplayName(toolName), utils.Reset)
	createCmd := exec.Command(systemPythonPath, "-m", "venv", venvPath)
	if out, err := runSetupCommand(createCmd); err != nil {
		return fmt.Errorf("venv creation failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	installCmd := exec.Command(pipPath, "install", repoPath)
	if out, err := runSetupCommand(installCmd); err != nil {
		return fmt.Errorf("temporary install failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	runCmd := exec.Command(pythonPath, append([]string{"-m", module}, args...)...)
	if normalizeToolKey(toolName) == "maigret" {
		runCmd.Dir = maigretOutputDir()
	}
	executeOSINTCommand(toolName, target, module, runCmd, time.Now())
	return nil
}

func runLocalPythonScriptCommand(toolName, target, repoPath string, scriptCandidates []string, args []string) bool {
	if !dirExists(repoPath) {
		return false
	}

	scriptPath := ""
	for _, candidate := range scriptCandidates {
		fullPath := filepath.Join(repoPath, candidate)
		if fileExists(fullPath) {
			scriptPath = fullPath
			break
		}
	}
	if scriptPath == "" {
		return false
	}

	pythonPath, err := resolveRepoPythonPath(repoPath)
	if err != nil {
		return false
	}

	cmd := exec.Command(pythonPath, append([]string{scriptPath}, args...)...)
	cmd.Dir = repoPath
	executeOSINTCommand(toolName, target, filepath.Base(scriptPath), cmd, time.Now())
	return true
}

func resolveRepoPythonPath(repoPath string) (string, error) {
	pythonPath, _ := venvPaths(filepath.Join(repoPath, ".venv"))
	if fileExists(pythonPath) {
		return pythonPath, nil
	}

	return resolveSystemPythonPath()
}

func resolveSystemPythonPath() (string, error) {
	for _, py := range []string{"python3", "python", "py"} {
		pyPath, err := resolveToolPath(py)
		if err == nil {
			return pyPath, nil
		}
	}
	return "", errors.New("python interpreter not found")
}

func canRunLocalPythonRepo(repoPath string) bool {
	if !dirExists(repoPath) {
		return false
	}
	_, err := resolveRepoPythonPath(repoPath)
	return err == nil
}

func venvPaths(venvPath string) (pythonPath string, pipPath string) {
	if runtime.GOOS == "windows" {
		return filepath.Join(venvPath, "Scripts", "python.exe"), filepath.Join(venvPath, "Scripts", "pip.exe")
	}
	return filepath.Join(venvPath, "bin", "python"), filepath.Join(venvPath, "bin", "pip")
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func dirExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func isDirWritable(dir string) bool {
	if !dirExists(dir) {
		return false
	}
	f, err := os.CreateTemp(dir, ".eclipse-w-*")
	if err != nil {
		return false
	}
	_ = f.Close()
	_ = os.Remove(f.Name())
	return true
}
