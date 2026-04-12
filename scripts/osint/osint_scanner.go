package osint

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

const (
	osintResultsFile = "target/osint_results.json"
	osintReportsDir  = "target/osint_reports"
	osintAPIKeysFile = "target/osint_api_keys.json"
	osintToolsDir    = "target/osint_tools"
)

var apiKeyHelpLinks = map[string]string{
	"SHODAN_API_KEY": "https://account.shodan.io/",
	"HIBP_API_KEY":   "https://haveibeenpwned.com/API/Key",
}

func OSINTToolkit() {
	utils.ClearTerminal()
	fmt.Printf("\n%s=== OSINT TOOLKIT ===%s\n\n", utils.Blue, utils.Reset)
	fmt.Printf("%sUse only on authorized targets and lawful investigations.%s\n\n", utils.Yellow, utils.Reset)

	reader := bufio.NewReader(os.Stdin)
	loadStoredAPIKeysIntoEnv()

	for {
		fmt.Printf("%s[1]  Whois lookup (domain/IP)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[2]  DNS recon (A/AAAA/MX/TXT/NS)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[3]  TheHarvester (domain)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[4]  Subdomain enum (subfinder/assetfinder/amass)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[5]  Shodan host lookup (CLI)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[6]  Shodan InternetDB (no API key)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[7]  Sherlock username check%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[8]  Recon-ng quick module run%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[9]  SpiderFoot quick scan%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[10] Have I Been Pwned (email)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[11] Maltego seed file (CSV)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[12] SocialEye.net lookup%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[13] Maigret web lookup%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[14] API Key Manager%s\n", utils.Blue, utils.Reset)
		utils.PrintReturnOption("15")
		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			if !ensureDependenciesForOSINTOption(reader, "1") {
				utils.WaitForEnter(reader)
				return
			}
			target := askTarget(reader, "Target (domain or IP)")
			if target == "" {
				fmt.Printf("%sTarget is required.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}
			runOSINTCommand("whois", target, "whois", []string{target})
			utils.WaitForEnter(reader)
			return
		case "2":
			if !ensureDependenciesForOSINTOption(reader, "2") {
				utils.WaitForEnter(reader)
				return
			}
			target := askTarget(reader, "Domain for DNS recon")
			if !isLikelyDomain(target) {
				fmt.Printf("%sInvalid domain format.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}
			runDNSRecon(target)
			utils.WaitForEnter(reader)
			return
		case "3":
			if !ensureDependenciesForOSINTOption(reader, "3") {
				utils.WaitForEnter(reader)
				return
			}
			target := askTarget(reader, "Domain for TheHarvester")
			if !isLikelyDomain(target) {
				fmt.Printf("%sInvalid domain format.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}
			runTheHarvester(target)
			utils.WaitForEnter(reader)
			return
		case "4":
			if !ensureDependenciesForOSINTOption(reader, "4") {
				utils.WaitForEnter(reader)
				return
			}
			target := askTarget(reader, "Domain for subdomain enum")
			if !isLikelyDomain(target) {
				fmt.Printf("%sInvalid domain format.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}
			runSubdomainEnum(target)
			utils.WaitForEnter(reader)
			return
		case "5":
			if !ensureAPIKeysForOption(reader, "5") {
				utils.WaitForEnter(reader)
				return
			}
			if !ensureDependenciesForOSINTOption(reader, "5") {
				utils.WaitForEnter(reader)
				return
			}
			ensureShodanCLIConfigured()
			target := askTarget(reader, "IP for Shodan host lookup")
			if !utils.IsValidIPv4(target) {
				fmt.Printf("%sInvalid IPv4 format.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}
			runOSINTCommand("shodan-cli", target, "shodan", []string{"host", target})
			utils.WaitForEnter(reader)
			return
		case "6":
			target := askTarget(reader, "IP for InternetDB")
			if !utils.IsValidIPv4(target) {
				fmt.Printf("%sInvalid IPv4 format.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}
			runShodanInternetDB(target)
			utils.WaitForEnter(reader)
			return
		case "7":
			if !ensureDependenciesForOSINTOption(reader, "7") {
				utils.WaitForEnter(reader)
				return
			}
			target := askTarget(reader, "Username for Sherlock")
			if target == "" {
				fmt.Printf("%sUsername is required.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}
			runOSINTCommand("sherlock", target, "sherlock", []string{"--print-found", target})
			utils.WaitForEnter(reader)
			return
		case "8":
			target := askTarget(reader, "Domain for Recon-ng")
			if !isLikelyDomain(target) {
				fmt.Printf("%sInvalid domain format.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}
			runReconNG(target)
			utils.WaitForEnter(reader)
			return
		case "9":
			target := askTarget(reader, "Domain/IP for SpiderFoot")
			if target == "" {
				fmt.Printf("%sTarget is required.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}
			runSpiderFootScan(target)
			utils.WaitForEnter(reader)
			return
		case "10":
			if !ensureAPIKeysForOption(reader, "10") {
				utils.WaitForEnter(reader)
				return
			}
			target := askTarget(reader, "Email for HIBP")
			if !isLikelyEmail(target) {
				fmt.Printf("%sInvalid email format.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}
			runHIBPCheck(target)
			utils.WaitForEnter(reader)
			return
		case "11":
			target := askTarget(reader, "Target for Maltego seed (domain/email/IP)")
			if target == "" {
				fmt.Printf("%sTarget is required.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}
			createMaltegoSeed(target)
			utils.WaitForEnter(reader)
			return
		case "12":
			target := askTarget(reader, "Target for SocialEye (username/email/name)")
			if target == "" {
				fmt.Printf("%sTarget is required.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}
			runSocialEyeLookup(target)
			utils.WaitForEnter(reader)
			return
		case "13":
			if !ensureDependenciesForOSINTOption(reader, "13") {
				utils.WaitForEnter(reader)
				return
			}
			target := askTarget(reader, "Username for Maigret")
			if target == "" {
				fmt.Printf("%sUsername is required.%s\n", utils.Red, utils.Reset)
				utils.WaitForEnter(reader)
				return
			}
			runMaigretLookup(reader, target)
			utils.WaitForEnter(reader)
			return
		case "14":
			manageAPIKeys(reader)
			utils.WaitForEnter(reader)
			return
		case "15":
			return
		default:
			fmt.Printf("%sInvalid option!%s\n\n", utils.Red, utils.Reset)
		}
	}
}

func askTarget(reader *bufio.Reader, label string) string {
	fmt.Printf("%s%s: %s", utils.Green, label, utils.Reset)
	val, _ := reader.ReadString('\n')
	return strings.TrimSpace(val)
}

func runDNSRecon(target string) {
	if isToolInstalled("dig") {
		runOSINTCommand("dns-a", target, "dig", []string{"+short", "A", target})
		runOSINTCommand("dns-aaaa", target, "dig", []string{"+short", "AAAA", target})
		runOSINTCommand("dns-mx", target, "dig", []string{"+short", "MX", target})
		runOSINTCommand("dns-txt", target, "dig", []string{"+short", "TXT", target})
		runOSINTCommand("dns-ns", target, "dig", []string{"+short", "NS", target})
		runOSINTCommand("dns-ptr", target, "dig", []string{"+short", "-x", target})
		return
	}
	runOSINTCommand("dns-a", target, "nslookup", []string{"-type=A", target})
	runOSINTCommand("dns-aaaa", target, "nslookup", []string{"-type=AAAA", target})
	runOSINTCommand("dns-mx", target, "nslookup", []string{"-type=MX", target})
	runOSINTCommand("dns-txt", target, "nslookup", []string{"-type=TXT", target})
	runOSINTCommand("dns-ns", target, "nslookup", []string{"-type=NS", target})
	runOSINTCommand("dns-ptr", target, "nslookup", []string{"-type=PTR", target})
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

func runMaigretLookup(reader *bufio.Reader, target string) {
	args := []string{target, "-a", "--html"}

	if isToolInstalled("maigret") {
		runOSINTCommand("maigret", target, "maigret", args)
		return
	}

	repoPath := filepath.Join(osintToolsDir, "maigret")
	if dirExists(repoPath) {
		fmt.Printf("%sMaigret is not installed globally. Create a temporary isolated env from the local repo for this run only? (y/N): %s", utils.Yellow, utils.Reset)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer == "y" || answer == "yes" {
			if err := runTempRepoPythonModuleCommand("maigret", target, repoPath, "maigret", args); err != nil {
				recordAndPrintError("maigret", target, fmt.Sprintf("Failed to run temporary Maigret environment: %v", err), time.Now())
			}
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

	if runLocalPythonModuleCommand("theharvester", target, filepath.Join(osintToolsDir, "theHarvester"), "theHarvester", args) {
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

	if runLocalPythonScriptCommand("recon-ng", target, filepath.Join(osintToolsDir, "recon-ng"), []string{"recon-ng", "recon-ng.py"}, []string{"-r", tmp}) {
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

	if runLocalPythonScriptCommand("spiderfoot", target, filepath.Join(osintToolsDir, "spiderfoot"), []string{"sf.py", "spiderfoot.py"}, []string{"-s", target, "-q"}) {
		return
	}

	recordAndPrintError("spiderfoot", target, buildMissingToolMessage("spiderfoot"), time.Now())
}

func runShodanInternetDB(ip string) {
	start := time.Now()
	url := "https://internetdb.shodan.io/" + ip
	resp, err := http.Get(url)
	if err != nil {
		msg := fmt.Sprintf("InternetDB request failed: %v", err)
		recordAndPrintError("shodan-internetdb", ip, msg, start)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		msg := fmt.Sprintf("InternetDB read failed: %v", err)
		recordAndPrintError("shodan-internetdb", ip, msg, start)
		return
	}

	outFile, saveErr := saveOSINTOutput("shodan-internetdb", ip, body)
	if saveErr != nil {
		msg := fmt.Sprintf("Failed to save output: %v", saveErr)
		recordAndPrintError("shodan-internetdb", ip, msg, start)
		return
	}

	rec := OSINTRecord{
		Tool:            "shodan-internetdb",
		Target:          ip,
		Status:          "ok",
		Summary:         "InternetDB lookup completed.",
		OutputFile:      outFile,
		DurationSeconds: time.Since(start).Seconds(),
		RanAt:           time.Now(),
	}
	recordOSINT(rec)
	fmt.Printf("%sSaved InternetDB result to %s%s\n", utils.Green, outFile, utils.Reset)
}

func runSocialEyeLookup(target string) {
	start := time.Now()
	escaped := url.QueryEscape(target)
	candidates := []string{
		"https://socialeye.net/search?q=" + escaped,
		"https://socialeye.net/?s=" + escaped,
		"https://socialeye.net/",
	}

	client := &http.Client{Timeout: 15 * time.Second}
	var body []byte
	var selectedURL string
	var statusCode int
	var lastErr error

	for _, endpoint := range candidates {
		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("user-agent", "G0-MULTITOOL-OSINT")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		data, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}

		statusCode = resp.StatusCode
		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			body = data
			selectedURL = endpoint
			break
		}
	}

	if len(body) == 0 {
		msg := "SocialEye request failed."
		if lastErr != nil {
			msg = fmt.Sprintf("SocialEye request failed: %v", lastErr)
		}
		recordAndPrintError("socialeye", target, msg, start)
		return
	}

	report := strings.Builder{}
	report.WriteString("Tool: SocialEye.net\n")
	report.WriteString("Target: " + target + "\n")
	report.WriteString("URL: " + selectedURL + "\n")
	report.WriteString("HTTP Status: " + strconv.Itoa(statusCode) + "\n")
	report.WriteString("Fetched At: " + time.Now().Format("2006-01-02 15:04:05") + "\n\n")
	plain := extractReadableTextFromHTML(string(body))
	title := extractHTMLTitle(string(body))
	isNotFound := statusCode == 404 || strings.Contains(strings.ToLower(plain), "404")

	if title != "" {
		report.WriteString("Page Title: " + title + "\n")
	}
	if isNotFound {
		report.WriteString("Result: No public result page found for this query (HTTP 404 / not-found).\n")
		report.WriteString("Hint: the target may not exist, or SocialEye may require a different/private workflow.\n")
	} else {
		if len(plain) > 1200 {
			plain = plain[:1200]
		}
		if plain == "" {
			plain = "No readable result text extracted."
		}
		report.WriteString("Extracted Summary:\n")
		report.WriteString(plain + "\n")
	}

	outFile, saveErr := saveOSINTOutput("socialeye", target, []byte(report.String()))
	if saveErr != nil {
		recordAndPrintError("socialeye", target, fmt.Sprintf("Failed to save output: %v", saveErr), start)
		return
	}

	recordOSINT(OSINTRecord{
		Tool:            "socialeye",
		Target:          target,
		Status:          "ok",
		Summary:         "SocialEye lookup completed.",
		OutputFile:      outFile,
		DurationSeconds: time.Since(start).Seconds(),
		RanAt:           time.Now(),
	})

	fmt.Printf("%sSaved SocialEye output to %s%s\n", utils.Green, outFile, utils.Reset)
	printOSINTOutputPreview("socialeye", []byte(report.String()))
}

func runHIBPCheck(email string) {
	start := time.Now()
	apiKey := strings.TrimSpace(os.Getenv("HIBP_API_KEY"))
	if apiKey == "" {
		recordAndPrintError("haveibeenpwned", email, "HIBP_API_KEY not set. Create one at: https://haveibeenpwned.com/API/Key", start)
		return
	}

	escaped := url.PathEscape(email)
	req, err := http.NewRequest("GET", "https://haveibeenpwned.com/api/v3/breachedaccount/"+escaped+"?truncateResponse=false", nil)
	if err != nil {
		recordAndPrintError("haveibeenpwned", email, fmt.Sprintf("Request creation failed: %v", err), start)
		return
	}
	req.Header.Set("hibp-api-key", apiKey)
	req.Header.Set("user-agent", "G0-MULTITOOL-OSINT")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		recordAndPrintError("haveibeenpwned", email, fmt.Sprintf("Request failed: %v", err), start)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		recordAndPrintError("haveibeenpwned", email, fmt.Sprintf("Response read failed: %v", err), start)
		return
	}

	if resp.StatusCode == 404 {
		outFile, saveErr := saveOSINTOutput("haveibeenpwned", email, []byte("No breach found for this account.\n"))
		if saveErr != nil {
			recordAndPrintError("haveibeenpwned", email, fmt.Sprintf("Failed to save output: %v", saveErr), start)
			return
		}
		recordOSINT(OSINTRecord{
			Tool:            "haveibeenpwned",
			Target:          email,
			Status:          "ok",
			Summary:         "No breach found.",
			OutputFile:      outFile,
			DurationSeconds: time.Since(start).Seconds(),
			RanAt:           time.Now(),
		})
		fmt.Printf("%sNo breach found. Saved result to %s%s\n", utils.Green, outFile, utils.Reset)
		return
	}

	if resp.StatusCode != 200 {
		recordAndPrintError("haveibeenpwned", email, fmt.Sprintf("HIBP API returned HTTP %d", resp.StatusCode), start)
		return
	}

	outFile, saveErr := saveOSINTOutput("haveibeenpwned", email, body)
	if saveErr != nil {
		recordAndPrintError("haveibeenpwned", email, fmt.Sprintf("Failed to save output: %v", saveErr), start)
		return
	}

	recordOSINT(OSINTRecord{
		Tool:            "haveibeenpwned",
		Target:          email,
		Status:          "warning",
		Summary:         "Breach records found for this account.",
		OutputFile:      outFile,
		DurationSeconds: time.Since(start).Seconds(),
		RanAt:           time.Now(),
	})
	fmt.Printf("%sPotential breaches found. Saved result to %s%s\n", utils.Yellow, outFile, utils.Reset)
}

func createMaltegoSeed(target string) {
	start := time.Now()
	if err := os.MkdirAll(osintReportsDir, 0755); err != nil {
		recordAndPrintError("maltego-seed", target, fmt.Sprintf("Cannot create reports dir: %v", err), start)
		return
	}

	name := buildOSINTOutputName("maltego-seed", target, "csv")
	fullPath := filepath.Join(osintReportsDir, name)
	entityType, description := classifyMaltegoSeedTarget(target)
	var csvBuffer bytes.Buffer
	writer := csv.NewWriter(&csvBuffer)
	_ = writer.Write([]string{"EntityType", "Value", "Description"})
	_ = writer.Write([]string{entityType, strings.TrimSpace(target), description})
	writer.Flush()
	if writerErr := writer.Error(); writerErr != nil {
		recordAndPrintError("maltego-seed", target, fmt.Sprintf("Cannot build CSV seed: %v", writerErr), start)
		return
	}

	if err := os.WriteFile(fullPath, csvBuffer.Bytes(), 0644); err != nil {
		recordAndPrintError("maltego-seed", target, fmt.Sprintf("Cannot write seed file: %v", err), start)
		return
	}

	recordOSINT(OSINTRecord{
		Tool:            "maltego-seed",
		Target:          target,
		Status:          "ok",
		Summary:         fmt.Sprintf("CSV seed file created for Maltego import (%s).", entityType),
		OutputFile:      fullPath,
		DurationSeconds: time.Since(start).Seconds(),
		RanAt:           time.Now(),
	})

	var summary strings.Builder
	summary.WriteString("MALTEGO SEED SUMMARY\n")
	summary.WriteString("What this does: creates a starter CSV (seed) to import into Maltego and start graph pivots/transforms.\n")
	summary.WriteString("Detected entity type: " + entityType + "\n")
	summary.WriteString("Target value: " + strings.TrimSpace(target) + "\n")
	summary.WriteString("Description: " + description + "\n")
	summary.WriteString("Rows written: 1\n")
	summary.WriteString("Output file: " + fullPath + "\n")
	summary.WriteString("\nHow to use in Maltego:\n")
	summary.WriteString("1. Open Maltego.\n")
	summary.WriteString("2. Import the CSV/Table file.\n")
	summary.WriteString("3. Map column 'Value' as the main entity value.\n")
	summary.WriteString("4. Run transforms on the imported entity.\n")

	fmt.Printf("%sMaltego seed created: %s%s\n", utils.Green, fullPath, utils.Reset)
	printOSINTOutputPreview("maltego-seed", []byte(summary.String()))
}

func classifyMaltegoSeedTarget(target string) (string, string) {
	v := strings.TrimSpace(target)
	switch {
	case isLikelyEmail(v):
		return "maltego.EmailAddress", "Email seed. Use this to pivot into breaches, usernames, domains, and people data."
	case utils.IsValidIPv4(v):
		return "maltego.IPv4Address", "IPv4 seed. Use this to pivot into ASN, hosting, services, and related infrastructure."
	case isLikelyDomain(v):
		return "maltego.Domain", "Domain seed. Use this to pivot into DNS, subdomains, certificates, and organization footprint."
	default:
		return "maltego.Phrase", "Generic phrase seed for manual investigation and custom transform pivots."
	}
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
	output, err := cmd.CombinedOutput()
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
	return cmd.CombinedOutput()
}

func saveOSINTOutput(toolName, target string, data []byte) (string, error) {
	if err := os.MkdirAll(osintReportsDir, 0755); err != nil {
		return "", err
	}
	filename := buildOSINTOutputName(toolName, target, "txt")
	fullPath := filepath.Join(osintReportsDir, filename)
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
	raw, err := os.ReadFile(osintResultsFile)
	if err == nil {
		_ = json.Unmarshal(raw, &history)
	}
	history.Records = append(history.Records, rec)
	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		fmt.Printf("%sCould not serialize OSINT history: %v%s\n", utils.Red, err, utils.Reset)
		return
	}
	if err := os.WriteFile(osintResultsFile, data, 0644); err != nil {
		fmt.Printf("%sCould not save OSINT history: %v%s\n", utils.Red, err, utils.Reset)
	}
}

func viewOSINTHistory() {
	utils.ClearTerminal()
	fmt.Printf("\n%s=== OSINT HISTORY ===%s\n\n", utils.Blue, utils.Reset)

	data, err := os.ReadFile(osintResultsFile)
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
	if utils.IsValidIPv4(v) {
		return false
	}
	re := regexp.MustCompile(`^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$`)
	return re.MatchString(v)
}

func isLikelyEmail(v string) bool {
	re := regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	return re.MatchString(strings.TrimSpace(v))
}

func ensureDependenciesForOSINTOption(reader *bufio.Reader, option string) bool {
	required := requiredDependenciesForOption(option)
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
		return true
	}

	fmt.Printf("%sInstall only these dependencies now? (y/N): %s", utils.Yellow, utils.Reset)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer != "y" && answer != "yes" {
		printDependencyInstallHints(missing)
		return true
	}

	runDependencyInstallCommands(installCommands)
	stillMissing := missingTools(required)
	if len(stillMissing) > 0 {
		fmt.Printf("%sStill missing after setup: %s%s\n", utils.Red, strings.Join(formatRequirementLabels(stillMissing), ", "), utils.Reset)
		printDependencyInstallHints(stillMissing)
		return true
	}
	return true
}

func requiredDependenciesForOption(option string) []string {
	switch option {
	case "1":
		return nil
	case "2":
		return nil
	case "3":
		if isToolInstalled("theHarvester") || canRunLocalPythonRepo(filepath.Join(osintToolsDir, "theHarvester")) {
			return nil
		}
		return []string{"python3|python|py", "pip3|pip"}
	case "4":
		return nil
	case "5":
		if isToolInstalled("shodan") {
			return nil
		}
		return []string{"python3|python|py", "pip3|pip"}
	case "7":
		if isToolInstalled("sherlock") {
			return nil
		}
		return []string{"python3|python|py", "pip3|pip"}
	case "13":
		if isToolInstalled("maigret") || canRunLocalPythonRepo(filepath.Join(osintToolsDir, "maigret")) {
			return nil
		}
		return []string{"python3|python|py", "pip3|pip"}
	case "8":
		return nil
	case "9":
		return nil
	default:
		return nil
	}
}

func requiredAPIKeysForOption(option string) []string {
	switch option {
	case "5":
		return []string{"SHODAN_API_KEY"}
	case "10":
		return []string{"HIBP_API_KEY"}
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

	allKeys := []string{"SHODAN_API_KEY", "HIBP_API_KEY"}
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
		if err := os.Remove(osintAPIKeysFile); err != nil && !os.IsNotExist(err) {
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
	data, err := os.ReadFile(osintAPIKeysFile)
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
	return os.WriteFile(osintAPIKeysFile, data, 0600)
}

func loadStoredAPIKeysIntoEnv() {
	store := loadAPIKeyStore()
	for k, v := range store {
		if strings.TrimSpace(v) != "" {
			_ = os.Setenv(k, v)
		}
	}
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
		}
	case "brew":
		switch key {
		case "whois":
			return []string{"brew install whois"}
		case "dns":
			return []string{"brew install bind"}
		case "python", "pip":
			return []string{"brew install python"}
		}
	case "winget":
		switch key {
		case "python":
			return []string{`winget install --id Python.Python.3 --accept-package-agreements --accept-source-agreements`}
		case "pip":
			return []string{`py -m ensurepip --upgrade || python -m ensurepip --upgrade`}
		}
	case "choco":
		switch key {
		case "python":
			return []string{`choco install -y python`}
		case "pip":
			return []string{`py -m ensurepip --upgrade || python -m ensurepip --upgrade`}
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
	data, err := os.ReadFile(osintResultsFile)
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
			// Ignore unknown commands and re-render current page.
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
	if err := os.Remove(osintResultsFile); err != nil && !os.IsNotExist(err) {
		fmt.Printf("%sFailed to delete %s: %v%s\n", utils.Red, osintResultsFile, err, utils.Reset)
		return
	}
	if err := os.RemoveAll(osintReportsDir); err != nil && !os.IsNotExist(err) {
		fmt.Printf("%sFailed to delete %s: %v%s\n", utils.Red, osintReportsDir, err, utils.Reset)
		return
	}
	if err := os.MkdirAll(osintReportsDir, 0755); err != nil {
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

		// Remove noisy progress/log lines.
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
			// Keep only discovered profiles/URLs.
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
	// Drop minified client-hydration payload artifacts common in modern JS frameworks.
	noise := []string{"self.__next_f", "window.__", "__NEXT_DATA__", "@keyframes", "function(", "=>"}
	for _, n := range noise {
		if strings.Contains(strings.ToLower(plain), strings.ToLower(n)) {
			plain = strings.ReplaceAll(plain, n, " ")
		}
	}
	return normalizeWhitespace(plain)
}

func resolveToolPath(name string) (string, error) {
	for _, candidateName := range toolNameCandidates(name) {
		if strings.ContainsRune(candidateName, os.PathSeparator) {
			if _, err := os.Stat(candidateName); err == nil {
				return candidateName, nil
			}
		}

		if p, err := exec.LookPath(candidateName); err == nil {
			return p, nil
		}

		for _, dir := range commonToolSearchDirs() {
			candidate := filepath.Join(dir, candidateName)
			if runtime.GOOS == "windows" {
				exts := []string{".exe", ".cmd", ".bat", ".ps1"}
				for _, ext := range exts {
					if _, err := os.Stat(candidate + ext); err == nil {
						return candidate + ext, nil
					}
				}
			}
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
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
	return cmd.CombinedOutput()
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
		return filepath.Join(osintToolsDir, "maigret")
	case "theharvester":
		return filepath.Join(osintToolsDir, "theHarvester")
	case "recon-ng":
		return filepath.Join(osintToolsDir, "recon-ng")
	case "spiderfoot":
		return filepath.Join(osintToolsDir, "spiderfoot")
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
	cmd.Dir = repoPath
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
