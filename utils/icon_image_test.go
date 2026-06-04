package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSupportedIconImageExt(t *testing.T) {
	valid := []string{"a.ico", "a.png", "a.jpg", "a.jpeg", "a.bmp", "a.gif", "a.tif", "a.tiff", "a.webp"}
	for _, path := range valid {
		if !SupportedIconImageExt(path) {
			t.Fatalf("expected %s to be supported", path)
		}
	}

	if SupportedIconImageExt("a.txt") {
		t.Fatal("txt should not be supported")
	}
}

func TestValidateIconImagePath(t *testing.T) {
	tmp := t.TempDir()
	imagePath := filepath.Join(tmp, "icon.png")
	if err := os.WriteFile(imagePath, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := ValidateIconImagePath(`"` + imagePath + `"`)
	if err != nil {
		t.Fatal(err)
	}
	if got != imagePath {
		t.Fatalf("expected %q, got %q", imagePath, got)
	}
}

func TestValidateIconImagePathRejectsEmpty(t *testing.T) {
	if _, err := ValidateIconImagePath("   "); err == nil {
		t.Fatal("expected empty path to fail")
	}
}
