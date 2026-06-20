package phone

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestLoadPhoneInfoGaCredentialsUsesTextFileOnly(t *testing.T) {
	t.Setenv("ECLIPSE_ROOT", t.TempDir())
	t.Setenv("NUMVERIFY_API_KEY", "from-env")
	t.Setenv("GOOGLE_API_KEY", "from-env")

	credentials, exists, err := loadPhoneInfoGaCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("credentials file should not exist")
	}
	if credentials["NUMVERIFY_API_KEY"] != "" || credentials["GOOGLE_API_KEY"] != "" {
		t.Fatalf("credentials should ignore environment values: %#v", credentials)
	}

	if err := os.MkdirAll(filepath.Dir(phoneInfoGaCredentialsFile()), 0755); err != nil {
		t.Fatal(err)
	}
	data := "NUMVERIFY_API_KEY=from-file\nGOOGLE_API_KEY=\nGOOGLECSE_CX=cx-value\n"
	if err := os.WriteFile(phoneInfoGaCredentialsFile(), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}

	credentials, exists, err = loadPhoneInfoGaCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("credentials file should exist")
	}
	if credentials["NUMVERIFY_API_KEY"] != "from-file" {
		t.Fatalf("NUMVERIFY_API_KEY = %q, want from-file", credentials["NUMVERIFY_API_KEY"])
	}
	if credentials["GOOGLE_API_KEY"] != "" {
		t.Fatalf("GOOGLE_API_KEY = %q, want empty from file", credentials["GOOGLE_API_KEY"])
	}
	if credentials["GOOGLECSE_CX"] != "cx-value" {
		t.Fatalf("GOOGLECSE_CX = %q, want cx-value", credentials["GOOGLECSE_CX"])
	}
}

func TestNormalizeScannerError(t *testing.T) {
	googleMessage := "HTTP 500: googleapi: Error 403: Custom Search API has not been used in project before or it is disabled, SERVICE_DISABLED"
	if got := normalizeScannerError("googlecse", googleMessage); !strings.Contains(got, "Enable customsearch.googleapis.com") {
		t.Fatalf("googlecse error = %q", got)
	}

	if got := normalizeScannerError("numverify", "HTTP 500: Invalid authentication credentials"); !strings.Contains(got, "Invalid NUMVERIFY_API_KEY") {
		t.Fatalf("numverify error = %q", got)
	}
}

func TestScannerResultDetailsForGoogleSearch(t *testing.T) {
	result := map[string]any{
		"general": []any{
			map[string]any{
				"dork": "intext:\"351928052835\"",
				"url":  "https://www.google.com/search?q=351928052835",
			},
		},
	}

	details := scannerResultDetails("googlesearch", result)
	if len(details) != 1 {
		t.Fatalf("details len = %d, want 1", len(details))
	}
	if !strings.Contains(details[0], "GENERAL") || !strings.Contains(details[0], "https://www.google.com/search") {
		t.Fatalf("details[0] = %q", details[0])
	}
}
