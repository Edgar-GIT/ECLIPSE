package utils

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

func OpenURL(targetURL string) error {
	targetURL = strings.TrimSpace(targetURL)
	if targetURL == "" {
		return fmt.Errorf("empty URL")
	}
	switch runtime.GOOS {
	case "windows":
		if err := startDetached("rundll32", "url.dll,FileProtocolHandler", targetURL); err == nil {
			return nil
		}
		return startDetached("cmd", "/c", "start", "", targetURL)
	case "darwin":
		return startDetached("open", targetURL)
	default:
		return openOnLinux(targetURL, "")
	}
}

func OpenLocalFile(absPath string) error {
	absPath, err := filepath.Abs(filepath.Clean(absPath))
	if err != nil {
		return err
	}
	if _, err := os.Stat(absPath); err != nil {
		return err
	}

	switch runtime.GOOS {
	case "windows":
		fileURL := PathToFileURL(absPath)
		if err := startDetached("rundll32", "url.dll,FileProtocolHandler", fileURL); err == nil {
			return nil
		}
		return startDetached("cmd", "/c", "start", "", fileURL)
	case "darwin":
		return startDetached("open", absPath)
	default:
		return openOnLinux(absPath, PathToFileURL(absPath))
	}
}

func OpenLocalHTML(absPath string) error {
	return OpenLocalFile(absPath)
}

func PathToFileURL(absPath string) string {
	absPath = filepath.Clean(absPath)
	if runtime.GOOS == "windows" {
		p := filepath.ToSlash(absPath)
		if len(p) >= 2 && p[1] == ':' {
			u := url.URL{Scheme: "file", Path: "/" + p}
			return u.String()
		}
	}
	if !filepath.IsAbs(absPath) {
		if a, err := filepath.Abs(absPath); err == nil {
			absPath = a
		}
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(absPath)}
	return u.String()
}

func openOnLinux(localPath, fileURL string) error {
	if strings.HasPrefix(strings.ToLower(localPath), "http://") || strings.HasPrefix(strings.ToLower(localPath), "https://") {
		fileURL = localPath
		localPath = ""
	}

	var attempts []commandAttempt

	if isKDE() {
		attempts = append(attempts,
			commandAttempt{"kde-open5", copyArgs(localPath)},
			commandAttempt{"kde-open", copyArgs(localPath)},
		)
	}

	if env := strings.TrimSpace(os.Getenv("BROWSER")); env != "" {
		parts := strings.Fields(env)
		if len(parts) > 0 {
			target := localPath
			if target == "" {
				target = fileURL
			}
			if target != "" {
				attempts = append(attempts, commandAttempt{parts[0], append(append([]string{}, parts[1:]...), target)})
			}
		}
	}

	if localPath != "" {
		attempts = append(attempts,
			commandAttempt{"xdg-open", []string{localPath}},
			commandAttempt{"gio", []string{"open", localPath}},
			commandAttempt{"firefox", []string{"--new-tab", localPath}},
			commandAttempt{"firefox", []string{localPath}},
			commandAttempt{"firefox-esr", []string{"--new-tab", localPath}},
			commandAttempt{"firefox-esr", []string{localPath}},
			commandAttempt{"librewolf", []string{"--new-tab", localPath}},
			commandAttempt{"librewolf", []string{localPath}},
			commandAttempt{"flatpak", []string{"run", "--filesystem=host", "org.mozilla.firefox", localPath}},
			commandAttempt{"flatpak", []string{"run", "--filesystem=host:ro", "org.mozilla.firefox", localPath}},
			commandAttempt{"flatpak", []string{"run", "--filesystem=host", "io.gitlab.librewolf-community", localPath}},
			commandAttempt{"chromium", []string{localPath}},
			commandAttempt{"chromium-browser", []string{localPath}},
			commandAttempt{"google-chrome-stable", []string{localPath}},
			commandAttempt{"google-chrome", []string{localPath}},
			commandAttempt{"brave-browser", []string{localPath}},
		)
	}

	if fileURL != "" {
		attempts = append(attempts,
			commandAttempt{"xdg-open", []string{fileURL}},
			commandAttempt{"gio", []string{"open", fileURL}},
			commandAttempt{"flatpak", []string{"run", "--filesystem=host", "org.mozilla.firefox", fileURL}},
			commandAttempt{"firefox", []string{"--new-tab", fileURL}},
			commandAttempt{"firefox", []string{fileURL}},
		)
	}

	var failures []string
	for _, attempt := range attempts {
		if len(attempt.args) == 0 {
			continue
		}
		if err := startDetached(attempt.name, attempt.args...); err == nil {
			return nil
		} else {
			failures = append(failures, fmt.Sprintf("%s %v", attempt.name, err))
		}
	}

	return fmt.Errorf("não foi possível abrir (tenta: xdg-open %q ou instala kde-cli-tools/zenity). Detalhes: %s",
		localPath, strings.Join(failures, "; "))
}

func copyArgs(path string) []string {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	return []string{path}
}

type commandAttempt struct {
	name string
	args []string
}

func startDetached(name string, args ...string) error {
	path, err := exec.LookPath(name)
	if err != nil {
		return err
	}
	cmd := exec.Command(path, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil
	if runtime.GOOS == "linux" {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	}
	return cmd.Start()
}

func isKDE() bool {
	for _, v := range []string{
		os.Getenv("XDG_CURRENT_DESKTOP"),
		os.Getenv("XDG_SESSION_DESKTOP"),
		os.Getenv("DESKTOP_SESSION"),
	} {
		lower := strings.ToLower(v)
		if strings.Contains(lower, "kde") || strings.Contains(lower, "plasma") {
			return true
		}
	}
	return false
}
