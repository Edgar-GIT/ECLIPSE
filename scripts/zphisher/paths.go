package zphisher

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	repoURL  = "https://github.com/htr-tech/zphisher.git"
	toolName = "zphisher"
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

func zphisherDir() string {
	return filepath.Join(workspaceRoot(), "exec_tools", toolName)
}

func zphisherScript() string {
	return filepath.Join(zphisherDir(), "zphisher.sh")
}

func execToolsDir() string {
	return filepath.Join(workspaceRoot(), "exec_tools")
}
