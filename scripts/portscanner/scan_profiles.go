package portscanner

import (
	"bufio"
	"fmt"
	"strings"

	"programa/utils"
)

func resolvePortScanOptions(reader *bufio.Reader) (PortScannerOptions, bool) {
	profile, ok := utils.PromptScanProfile(reader)
	if !ok {
		return PortScannerOptions{}, false
	}

	switch profile {
	case "fast":
		opts := fastPortScannerOptions()
		printPortProfileSummary(opts, "fast")
		return opts, true
	case "medium":
		opts := mediumPortScannerOptions()
		printPortProfileSummary(opts, "medium")
		return opts, true
	case "full":
		opts := fullPortScannerOptions()
		printPortProfileSummary(opts, "full")
		return opts, true
	case "custom":
		opts := promptPortScannerFlags(reader)
		printPortProfileSummary(opts, "custom")
		return opts, true
	default:
		return PortScannerOptions{}, false
	}
}

func promptPortScannerFlags(reader *bufio.Reader) PortScannerOptions {
	fmt.Printf("\n%sFlags (Enter = defaults). Examples:%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s  -sT -sV -O -T4 --concurrency 512 --timeout 900ms --rate 1000/s%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("%s  Type help for all flags.%s\n", utils.Yellow, utils.Reset)
	fmt.Printf("%sOptions: %s", utils.Green, utils.Reset)
	raw, _ := reader.ReadString('\n')
	if strings.EqualFold(strings.TrimSpace(raw), "help") {
		printPortScannerFlagHelp()
		return promptPortScannerFlags(reader)
	}
	return parsePortScannerOptions(raw)
}

func fastPortScannerOptions() PortScannerOptions {
	return defaultPortScannerOptions()
}

func mediumPortScannerOptions() PortScannerOptions {
	opts := defaultPortScannerOptions()
	opts.TimingTemplate = 4
	applyPortTimingTemplate(&opts)
	opts.VersionDetection = true
	opts.VersionIntensity = 7
	opts.OSDetection = true
	opts.OutputFormat = "all"
	opts.ScriptNames = []string{"default"}
	opts.NoScripts = false
	return opts
}

func fullPortScannerOptions() PortScannerOptions {
	opts := completePortScannerOptions("tcp-connect")
	opts.TimingTemplate = 5
	applyPortTimingTemplate(&opts)
	opts.SafetyNotes = append(opts.SafetyNotes, "Full profile: T5 timing, version/OS detection, scripts, maximum concurrency.")
	return opts
}

func completePortScannerOptionsForProfile(profile string, scanType string) PortScannerOptions {
	switch profile {
	case "fast":
		opts := defaultPortScannerOptions()
		opts.ScanType = scanType
		opts.RequestedScan = scanType
		return opts
	case "medium":
		opts := mediumPortScannerOptions()
		opts.ScanType = scanType
		opts.RequestedScan = scanType
		return opts
	default:
		opts := completePortScannerOptions(scanType)
		if profile == "full" {
			opts.TimingTemplate = 5
			applyPortTimingTemplate(&opts)
		}
		return opts
	}
}

func printPortProfileSummary(opts PortScannerOptions, name string) {
	scripts := "off"
	if !opts.NoScripts && len(opts.ScriptNames) > 0 {
		scripts = strings.Join(opts.ScriptNames, ",")
	}
	fmt.Printf("%sPerfil %s: %s · T%d · concurrency=%d · timeout=%s · scripts=%s%s\n",
		utils.Yellow, name, opts.ScanType, opts.TimingTemplate, opts.Concurrency, opts.Timeout, scripts, utils.Reset)
}
