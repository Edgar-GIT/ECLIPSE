package nethunter

import (
	"strings"
	"testing"
)

func TestBuildDnsmasqConfigInternetDoesNotCaptureAllDNS(t *testing.T) {
	got := buildDnsmasqConfig(APConfig{
		SSID:            "lab",
		Interface:       "wlan0",
		ProvideInternet: true,
	}, "/tmp/ecl-extra.conf", "/tmp/ecl.leases")

	if strings.Contains(got, "address=/#/10.0.0.1") {
		t.Fatalf("internet mode must not capture all DNS: %s", got)
	}
	if strings.Contains(got, "dhcp-option=114") {
		t.Fatalf("internet mode must not advertise captive portal: %s", got)
	}
	if !strings.Contains(got, "server=1.1.1.1") || !strings.Contains(got, "server=8.8.8.8") {
		t.Fatalf("internet mode should keep upstream resolvers: %s", got)
	}
}

func TestBuildDnsmasqConfigCaptiveAdvertisesPortal(t *testing.T) {
	got := buildDnsmasqConfig(APConfig{
		SSID:          "lab",
		Interface:     "wlan0",
		CaptivePortal: true,
	}, "/tmp/ecl-extra.conf", "/tmp/ecl.leases")

	if !strings.Contains(got, "dhcp-option=114,http://10.0.0.1/") {
		t.Fatalf("captive mode should advertise portal URL: %s", got)
	}
}

func TestBuildDnsmasqAddressRulesCaptiveAndSpoof(t *testing.T) {
	got := buildDnsmasqAddressRules(true, map[string]string{
		"example.com": "192.0.2.10",
	})

	for _, want := range []string{
		"address=/#/10.0.0.1",
		"address=/example.com/192.0.2.10",
		"address=/www.example.com/192.0.2.10",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %s", want, got)
		}
	}
}

func TestParseRouteInterfaceSkipsAPInterface(t *testing.T) {
	output := "default via 10.0.0.1 dev wlan0 proto dhcp src 10.0.0.20 metric 600\ndefault via 172.20.10.1 dev usb0 proto dhcp src 172.20.10.2 metric 100\n"

	got := parseRouteInterface(output, "wlan0")
	if got != "usb0" {
		t.Fatalf("expected usb0, got %q", got)
	}
}
