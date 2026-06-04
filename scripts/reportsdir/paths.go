package reportsdir

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

func WorkspaceRoot() string {
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

func Root() string {
	return filepath.Join(WorkspaceRoot(), "reports")
}

func OSINTReports() string {
	return filepath.Join(Root(), "osint_reports")
}

func Zphisher() string {
	return filepath.Join(Root(), "zphisher")
}

func ZphisherAuth() string {
	return filepath.Join(Zphisher(), "auth")
}

func ZphisherSessions() string {
	return filepath.Join(Zphisher(), "sessions")
}
