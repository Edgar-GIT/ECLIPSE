package imganalysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSaveImageReportUsesReportsImageReportsDir(t *testing.T) {
	withTempWorkingDir(t)

	savedPath, err := saveImageReport(filepath.Join("input", "sample.png"), "report body")
	if err != nil {
		t.Fatal(err)
	}

	wantPart := filepath.Join("reports", "image_reports")
	if !strings.Contains(savedPath, wantPart) {
		t.Fatalf("expected path to contain %q, got %q", wantPart, savedPath)
	}

	if _, err := os.Stat(filepath.Join("reports", "image_reports")); err != nil {
		t.Fatalf("expected reports image directory: %v", err)
	}
}

func TestSaveImageHistoryRecordUsesReportsImageReportsDir(t *testing.T) {
	withTempWorkingDir(t)

	err := saveImageHistoryRecord(ImageAnalysisRecord{
		AnalyzedAt: time.Now(),
		ImagePath:  "sample.png",
		ImageName:  "sample.png",
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join("reports", "image_reports", "image_analysis_history.json")); err != nil {
		t.Fatalf("expected image history in reports image directory: %v", err)
	}

	if _, err := os.Stat("image_analysis_history.json"); !os.IsNotExist(err) {
		t.Fatalf("expected no root image history file, got err=%v", err)
	}
}

func withTempWorkingDir(t *testing.T) {
	t.Helper()

	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte("module test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ECLIPSE_ROOT", tmp)

	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWd); err != nil {
			t.Fatal(err)
		}
	})
}
