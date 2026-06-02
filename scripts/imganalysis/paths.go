package imganalysis

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	wsOnce sync.Once
	wsVal  string
)

func workspaceRoot() string {
	if v := strings.TrimSpace(os.Getenv("ECLIPSE_ROOT")); v != "" {
		return filepath.Clean(v)
	}
	wsOnce.Do(initWorkspaceRoot)
	return wsVal
}

func initWorkspaceRoot() {
	try := func(start string) (string, bool) {
		for d := filepath.Clean(start); d != "" && d != "."; d = filepath.Dir(d) {
			if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
				return d, true
			}
		}
		return "", false
	}
	if wd, err := os.Getwd(); err == nil {
		if r, ok := try(wd); ok {
			wsVal = r
			return
		}
	}
	if exe, err := os.Executable(); err == nil {
		if r, ok := try(filepath.Dir(exe)); ok {
			wsVal = r
			return
		}
	}
	if wd, err := os.Getwd(); err == nil {
		wsVal = wd
		return
	}
	wsVal = "."
}

func imageReportsDir() string {
	return filepath.Join(workspaceRoot(), "reports", "image_reports")
}

func imageHistoryFile() string {
	return filepath.Join(imageReportsDir(), "image_analysis_history.json")
}

func legacyImageHistoryFile() string {
	return filepath.Join(workspaceRoot(), "image_analysis_history.json")
}
