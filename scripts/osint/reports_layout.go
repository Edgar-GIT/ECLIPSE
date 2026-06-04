package osint

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"programa/scripts/reportsdir"
)

var migrateOSINTReportsOnce sync.Once

func pathOSINTReports() string {
	migrateOSINTReportsOnce.Do(migrateLegacyOSINTReports)
	d := reportsdir.OSINTReports()
	_ = os.MkdirAll(d, 0755)
	return d
}

func migrateLegacyOSINTReports() {
	newRoot := reportsdir.OSINTReports()
	oldRoot := filepath.Join(workspaceRoot(), "target", "osint_reports")
	if oldRoot == newRoot {
		return
	}
	if !dirExists(oldRoot) {
		return
	}
	_ = os.MkdirAll(newRoot, 0755)
	entries, err := os.ReadDir(oldRoot)
	if err != nil {
		return
	}
	for _, e := range entries {
		from := filepath.Join(oldRoot, e.Name())
		to := filepath.Join(newRoot, e.Name())
		if _, err := os.Stat(to); err == nil {
			continue
		}
		_ = os.Rename(from, to)
	}
	_ = os.RemoveAll(oldRoot)
}

func maigretOutputDir() string {
	d := filepath.Join(pathOSINTReports(), "maigret")
	_ = os.MkdirAll(d, 0755)
	return d
}

func theHarvesterOutputDir() string {
	d := filepath.Join(pathOSINTReports(), "theharvester")
	_ = os.MkdirAll(d, 0755)
	return d
}

func spiderfootOutputDir() string {
	d := filepath.Join(pathOSINTReports(), "spiderfoot")
	_ = os.MkdirAll(d, 0755)
	return d
}

func toolOutputDir(toolName string) string {
	switch normalizeToolKey(toolName) {
	case "maigret":
		return maigretOutputDir()
	case "theharvester":
		return theHarvesterOutputDir()
	case "spiderfoot":
		return spiderfootOutputDir()
	default:
		return pathOSINTReports()
	}
}

func countHTMLInDir(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".html") {
			n++
		}
	}
	return n
}

func relocateStrayHTML(toolName, destDir string) {
	if destDir == "" {
		return
	}
	roots := []string{
		workspaceRoot(),
		pathExecTools(),
		filepath.Join(pathExecTools(), "maigret"),
		filepath.Join(pathExecTools(), "theHarvester"),
		filepath.Join(pathExecTools(), "spiderfoot"),
	}
	seen := map[string]struct{}{}
	for _, root := range roots {
		if root == "" || !dirExists(root) {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if strings.Count(strings.TrimPrefix(path, root), string(os.PathSeparator)) > 3 {
					return filepath.SkipDir
				}
				if path == destDir || strings.HasPrefix(path, destDir+string(os.PathSeparator)) {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(strings.ToLower(d.Name()), ".html") {
				return nil
			}
			if !shouldRelocateHTML(toolName, d.Name()) {
				return nil
			}
			if _, ok := seen[path]; ok {
				return nil
			}
			seen[path] = struct{}{}
			target := filepath.Join(destDir, d.Name())
			if path == target {
				return nil
			}
			if _, err := os.Stat(target); err == nil {
				target = filepath.Join(destDir, toolName+"_"+d.Name())
			}
			_ = os.Rename(path, target)
			return nil
		})
	}
}

func shouldRelocateHTML(toolName, filename string) bool {
	lower := strings.ToLower(filename)
	switch normalizeToolKey(toolName) {
	case "maigret":
		return strings.HasPrefix(lower, "report_") || lower == "simple.html"
	case "theharvester", "spiderfoot":
		return true
	default:
		return strings.HasPrefix(lower, "report_")
	}
}
