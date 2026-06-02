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
		return openOnLinux("", targetURL)
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

func openOnLinux(localPath, remoteOrFileURL string) error {
	if strings.HasPrefix(strings.ToLower(localPath), "http://") || strings.HasPrefix(strings.ToLower(localPath), "https://") {
		remoteOrFileURL = localPath
		localPath = ""
	}

	attempts := linuxOpenAttempts(localPath, remoteOrFileURL)

	var failures []string
	for _, attempt := range attempts {
		if len(attempt.args) == 0 {
			continue
		}
		if err := startDetached(attempt.name, attempt.args...); err == nil {
			return nil
		} else {
			failures = append(failures, fmt.Sprintf("%s: %v", attempt.name, err))
		}
	}

	target := localPath
	if target == "" {
		target = remoteOrFileURL
	}
	return fmt.Errorf("não foi possível abrir %q (tenta: xdg-open %q). Detalhes: %s",
		target, localPath, strings.Join(failures, "; "))
}

func linuxOpenAttempts(localPath, fileURL string) []commandAttempt {
	var attempts []commandAttempt

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
			commandAttempt{"mimeopen", []string{"-L", localPath}},
			commandAttempt{"kde-open5", []string{localPath}},
			commandAttempt{"kde-open", []string{localPath}},
			commandAttempt{"exo-open", []string{localPath}},
			commandAttempt{"gnome-open", []string{localPath}},
			commandAttempt{"handlr", []string{"open", localPath}},
		)
		attempts = append(attempts, linuxBrowserAttempts(localPath)...)
	}

	if fileURL != "" && fileURL != localPath {
		attempts = append(attempts,
			commandAttempt{"xdg-open", []string{fileURL}},
			commandAttempt{"gio", []string{"open", fileURL}},
			commandAttempt{"handlr", []string{"open", fileURL}},
		)
		attempts = append(attempts, linuxBrowserAttempts(fileURL)...)
	}

	return dedupeAttempts(attempts)
}

func linuxBrowserAttempts(target string) []commandAttempt {
	return []commandAttempt{
		{"firefox", []string{"--new-tab", target}},
		{"firefox", []string{target}},
		{"firefox-esr", []string{"--new-tab", target}},
		{"firefox-esr", []string{target}},
		{"librewolf", []string{"--new-tab", target}},
		{"librewolf", []string{target}},
		{"flatpak", []string{"run", "--filesystem=host", "org.mozilla.firefox", target}},
		{"flatpak", []string{"run", "--filesystem=host:ro", "org.mozilla.firefox", target}},
		{"flatpak", []string{"run", "--filesystem=host", "io.gitlab.librewolf-community", target}},
		{"chromium", []string{target}},
		{"chromium-browser", []string{target}},
		{"google-chrome-stable", []string{target}},
		{"google-chrome", []string{target}},
		{"brave-browser", []string{target}},
		{"opera", []string{target}},
		{"vivaldi", []string{target}},
	}
}

func dedupeAttempts(attempts []commandAttempt) []commandAttempt {
	seen := make(map[string]struct{}, len(attempts))
	out := make([]commandAttempt, 0, len(attempts))
	for _, a := range attempts {
		if len(a.args) == 0 {
			continue
		}
		key := a.name + "\x00" + strings.Join(a.args, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, a)
	}
	return out
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
