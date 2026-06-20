package phone

import "testing"

func TestNormalizePhoneNumber(t *testing.T) {
	got := normalizePhoneNumber(" +(351) 912-345-678 ")
	want := "351912345678"
	if got != want {
		t.Fatalf("normalizePhoneNumber() = %q, want %q", got, want)
	}
}

func TestIsPhoneInfoGaNumber(t *testing.T) {
	valid := []string{"14155552671", "351912345678"}
	for _, value := range valid {
		if !isPhoneInfoGaNumber(value) {
			t.Fatalf("isPhoneInfoGaNumber(%q) = false", value)
		}
	}

	invalid := []string{"+14155552671", "0123456789", "123456", "1234567890123456", "351 912"}
	for _, value := range invalid {
		if isPhoneInfoGaNumber(value) {
			t.Fatalf("isPhoneInfoGaNumber(%q) = true", value)
		}
	}
}

func TestAPIErrorMessage(t *testing.T) {
	if got := apiErrorMessage([]byte(`{"result":{"error":"kept in result"}}`)); got != "" {
		t.Fatalf("apiErrorMessage() = %q, want empty", got)
	}
	if got := apiErrorMessage([]byte(`{"success":false,"message":"failed"}`)); got != "failed" {
		t.Fatalf("apiErrorMessage() = %q, want failed", got)
	}
	if got := apiErrorMessage([]byte(`{"error":"boom"}`)); got != "boom" {
		t.Fatalf("apiErrorMessage() = %q, want boom", got)
	}
}

func TestScannerSkipReason(t *testing.T) {
	info := phoneInfoGaNumber{CountryCode: 351}
	credentials := phoneInfoGaCredentials{}

	if got := scannerSkipReason("numverify", info, credentials); got == "" {
		t.Fatal("numverify without key should be skipped")
	}
	if got := scannerSkipReason("googlecse", info, credentials); got == "" {
		t.Fatal("googlecse without keys should be skipped")
	}
	if got := scannerSkipReason("ovh", info, credentials); got == "" {
		t.Fatal("ovh should skip unsupported Portuguese country code")
	}
	if got := scannerSkipReason("local", info, credentials); got != "" {
		t.Fatalf("local skip reason = %q, want empty", got)
	}
}

func TestScannerOptions(t *testing.T) {
	credentials := phoneInfoGaCredentials{
		"NUMVERIFY_API_KEY": "numverify-secret",
		"GOOGLE_API_KEY":    "google-secret",
		"GOOGLECSE_CX":      "cx-value",
	}

	if got := scannerOptions("numverify", credentials)["NUMVERIFY_API_KEY"]; got != "numverify-secret" {
		t.Fatalf("numverify option = %v", got)
	}
	options := scannerOptions("googlecse", credentials)
	if options["GOOGLE_API_KEY"] != "google-secret" || options["GOOGLECSE_CX"] != "cx-value" {
		t.Fatalf("googlecse options = %#v", options)
	}
}

func TestRecordStatusWithSkippedScanners(t *testing.T) {
	rec := phoneInfoGaRecord{
		NumberInfo: &phoneInfoGaNumber{Valid: true},
		Scanners: []phoneInfoGaScannerRun{
			{Name: "local", Status: "ok"},
			{Name: "ovh", Status: "skipped"},
		},
	}
	if got := recordStatus(rec); got != "PARTIAL" {
		t.Fatalf("recordStatus() = %q, want PARTIAL", got)
	}

	rec.Scanners = []phoneInfoGaScannerRun{{Name: "ovh", Status: "skipped"}}
	if got := recordStatus(rec); got != "SKIPPED" {
		t.Fatalf("recordStatus() = %q, want SKIPPED", got)
	}
}
