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
