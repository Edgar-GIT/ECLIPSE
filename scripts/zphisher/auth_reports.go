package zphisher

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"programa/scripts/reportsdir"
)

const (
	authIPFile   = "ip.txt"
	authCredsFile = "usernames.dat"
)

func prepareAuthReports() error {
	if err := os.MkdirAll(reportsdir.ZphisherAuth(), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(reportsdir.ZphisherSessions(), 0755); err != nil {
		return err
	}
	migrateLegacyAuthDir(filepath.Join(zphisherDir(), "auth"), reportsdir.ZphisherAuth())
	return linkToolAuthDir()
}

func linkToolAuthDir() error {
	toolAuth := filepath.Join(zphisherDir(), "auth")
	reportsAuth := reportsdir.ZphisherAuth()

	if isSymlinkTo(toolAuth, reportsAuth) {
		return nil
	}

	if dirExists(toolAuth) {
		migrateLegacyAuthDir(toolAuth, reportsAuth)
		if err := os.RemoveAll(toolAuth); err != nil {
			return err
		}
	}

	if runtime.GOOS == "windows" {
		return copyTree(reportsAuth, toolAuth)
	}

	rel, err := filepath.Rel(filepath.Dir(toolAuth), reportsAuth)
	if err != nil {
		rel = reportsAuth
	}
	return os.Symlink(rel, toolAuth)
}

func snapshotSessionAfterRun() (string, error) {
	authDir := reportsdir.ZphisherAuth()
	if !dirExists(authDir) {
		return "", nil
	}

	hasData := false
	for _, name := range []string{authIPFile, authCredsFile} {
		if fileExists(filepath.Join(authDir, name)) {
			info, err := os.Stat(filepath.Join(authDir, name))
			if err == nil && info.Size() > 0 {
				hasData = true
				break
			}
		}
	}
	if !hasData {
		return "", nil
	}

	sessionID := time.Now().Format("20060102_150405")
	dest := filepath.Join(reportsdir.ZphisherSessions(), sessionID)
	if err := os.MkdirAll(dest, 0755); err != nil {
		return "", err
	}

	for _, name := range []string{authIPFile, authCredsFile} {
		src := filepath.Join(authDir, name)
		if !fileExists(src) {
			continue
		}
		if err := copyFile(src, filepath.Join(dest, name)); err != nil {
			return "", err
		}
	}

	readme := fmt.Sprintf("Zphisher session %s\nSource: %s\n", sessionID, reportsdir.ZphisherAuth())
	_ = os.WriteFile(filepath.Join(dest, "README.txt"), []byte(readme), 0644)
	return dest, nil
}

func migrateLegacyAuthDir(src, dst string) {
	if !dirExists(src) || isSymlinkTo(src, dst) {
		return
	}
	_ = os.MkdirAll(dst, 0755)
	for _, name := range []string{authIPFile, authCredsFile} {
		from := filepath.Join(src, name)
		to := filepath.Join(dst, name)
		if !fileExists(from) {
			continue
		}
		if !fileExists(to) {
			_ = copyFile(from, to)
			continue
		}
		appendFile(to, from)
	}
}

func isSymlinkTo(path, target string) bool {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return false
	}
	link, err := os.Readlink(path)
	if err != nil {
		return false
	}
	if !filepath.IsAbs(link) {
		link = filepath.Join(filepath.Dir(path), link)
	}
	absTarget, _ := filepath.Abs(target)
	absLink, _ := filepath.Abs(link)
	return absLink == absTarget
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func appendFile(dst, src string) error {
	existing, err := os.ReadFile(dst)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	incoming, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		existing = append(existing, '\n')
	}
	return os.WriteFile(dst, append(existing, incoming...), 0644)
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		return copyFile(path, target)
	})
}
