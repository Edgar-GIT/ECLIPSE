package ipscanner

import (
	"bufio"
	"fmt"
	"strings"

	"programa/utils"
)

func resolveIPScanOptions(reader *bufio.Reader) (IPScannerOptions, bool) {
	profile, ok := utils.PromptScanProfile(reader)
	if !ok {
		return IPScannerOptions{}, false
	}

	switch profile {
	case "fast":
		opts := fastIPScannerOptions()
		printIPProfileSummary(opts, "fast")
		return opts, true
	case "medium":
		opts := mediumIPScannerOptions()
		printIPProfileSummary(opts, "medium")
		return opts, true
	case "full":
		opts := fullIPScannerOptions()
		printIPProfileSummary(opts, "full")
		return opts, true
	case "custom":
		opts := promptIPScannerOptions(reader)
		printIPProfileSummary(opts, "custom")
		return opts, true
	default:
		return IPScannerOptions{}, false
	}
}

func fastIPScannerOptions() IPScannerOptions {
	return defaultIPScannerOptions()
}

func mediumIPScannerOptions() IPScannerOptions {
	opts := defaultIPScannerOptions()
	opts.TimingTemplate = 4
	applyIPTimingTemplate(&opts)
	opts.DiscoveryMethods = []string{"icmp", "tcp", "udp"}
	opts.TCPPorts = []int{22, 25, 53, 80, 110, 139, 143, 443, 445, 587, 993, 995, 3389, 8080}
	opts.UDPPorts = []int{53, 123, 161}
	opts.EnableGeo = true
	opts.EnableRDNS = true
	opts.EnableScripts = true
	return opts
}

func fullIPScannerOptions() IPScannerOptions {
	opts := completeIPScannerOptions()
	opts.TimingTemplate = 5
	applyIPTimingTemplate(&opts)
	opts.DiscoveryMethods = []string{"icmp", "timestamp", "netmask", "tcp", "udp", "arp", "sctp"}
	opts.TCPPorts = []int{20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443}
	opts.UDPPorts = []int{53, 67, 68, 69, 123, 161, 500, 4500}
	opts.OutputFormat = "all"
	opts.SafetyNotes = append(opts.SafetyNotes, "Full profile: maximum discovery probes, enrichment, and T5 timing.")
	return opts
}

func printIPProfileSummary(opts IPScannerOptions, name string) {
	fmt.Printf("%sPerfil %s: T%d · concurrency=%d · timeout=%s · discovery=%s%s\n",
		utils.Yellow, name, opts.TimingTemplate, opts.Concurrency, opts.Timeout,
		strings.Join(opts.DiscoveryMethods, ","), utils.Reset)
}
