package pcutilities

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
	wsOnce.Do(initWorkspaceRoot)
	return wsVal
}

func initWorkspaceRoot() {
	if v := strings.TrimSpace(os.Getenv("ECLIPSE_ROOT")); v != "" {
		wsVal = filepath.Clean(v)
		return
	}
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

func pathPCReportsDir() string {
	return filepath.Join(workspaceRoot(), "target", "pc_reports")
}
