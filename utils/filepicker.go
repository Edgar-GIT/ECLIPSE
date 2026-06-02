package utils

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var errPickerCanceled = errors.New("file picker canceled")

type FilePickerConfig struct {
	Title       string
	DefaultDir  string
	FileFilter  string
	SaveAs      string
}

func PickOpenFile(cfg FilePickerConfig) (string, error) {
	cfg = normalizePickerConfig(cfg)
	switch runtime.GOOS {
	case "windows":
		return pickOpenFileWindows(cfg)
	case "darwin":
		return pickOpenFileDarwin(cfg)
	case "linux":
		return pickOpenFileLinux(cfg)
	default:
		return "", fmt.Errorf("file picker not supported on %s", runtime.GOOS)
	}
}

func PickSaveFile(cfg FilePickerConfig) (string, error) {
	cfg = normalizePickerConfig(cfg)
	switch runtime.GOOS {
	case "windows":
		return pickSaveFileWindows(cfg)
	case "linux":
		return pickSaveFileLinux(cfg)
	default:
		return "", fmt.Errorf("save dialog not supported on %s", runtime.GOOS)
	}
}

func normalizePickerConfig(cfg FilePickerConfig) FilePickerConfig {
	if strings.TrimSpace(cfg.Title) == "" {
		cfg.Title = "Select file"
	}
	if strings.TrimSpace(cfg.DefaultDir) == "" {
		if home, err := os.UserHomeDir(); err == nil {
			cfg.DefaultDir = home
		} else {
			cfg.DefaultDir = "."
		}
	}
	cfg.DefaultDir = filepath.Clean(cfg.DefaultDir)
	return cfg
}

func pickOpenFileWindows(cfg FilePickerConfig) (string, error) {
	filter := cfg.FileFilter
	if filter == "" {
		filter = "All Files (*.*)|*.*"
	}
	psScript := "$ErrorActionPreference='Stop';" +
		"Add-Type -AssemblyName System.Windows.Forms;" +
		"$f=New-Object System.Windows.Forms.OpenFileDialog;" +
		"$f.Title='" + escapePSSingleQuoted(cfg.Title) + "';" +
		"$f.InitialDirectory='" + escapePSSingleQuoted(cfg.DefaultDir) + "';" +
		"$f.Filter='" + escapePSSingleQuoted(filter) + "';" +
		"if($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){[Console]::Out.Write($f.FileName)}"
	out, err := exec.Command("powershell", "-NoProfile", "-Command", psScript).Output()
	if err != nil {
		return "", fmt.Errorf("file picker canceled or error: %w", err)
	}
	selected := strings.TrimSpace(string(out))
	if selected == "" {
		return "", errPickerCanceled
	}
	return selected, nil
}

func pickSaveFileWindows(cfg FilePickerConfig) (string, error) {
	filter := cfg.FileFilter
	if filter == "" {
		filter = "All Files (*.*)|*.*"
	}
	name := cfg.SaveAs
	if name == "" {
		name = "output"
	}
	psScript := "$ErrorActionPreference='Stop';" +
		"Add-Type -AssemblyName System.Windows.Forms;" +
		"$f=New-Object System.Windows.Forms.SaveFileDialog;" +
		"$f.Title='" + escapePSSingleQuoted(cfg.Title) + "';" +
		"$f.InitialDirectory='" + escapePSSingleQuoted(cfg.DefaultDir) + "';" +
		"$f.FileName='" + escapePSSingleQuoted(name) + "';" +
		"$f.Filter='" + escapePSSingleQuoted(filter) + "';" +
		"if($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){[Console]::Out.Write($f.FileName)}"
	out, err := exec.Command("powershell", "-NoProfile", "-Command", psScript).Output()
	if err != nil {
		return "", fmt.Errorf("save dialog canceled or error: %w", err)
	}
	selected := strings.TrimSpace(string(out))
	if selected == "" {
		return "", errPickerCanceled
	}
	return selected, nil
}

func pickOpenFileDarwin(cfg FilePickerConfig) (string, error) {
	script := `POSIX path of (choose file with prompt "` + escapeAppleScript(cfg.Title) + `")`
	out, err := exec.Command("osascript", "-e", script).Output()
	if err != nil {
		return "", fmt.Errorf("file picker canceled or error: %w", err)
	}
	selected := strings.TrimSpace(string(out))
	if selected == "" {
		return "", errPickerCanceled
	}
	return selected, nil
}

func pickOpenFileLinux(cfg FilePickerConfig) (string, error) {
	startDir := cfg.DefaultDir + string(os.PathSeparator)
	var attempts []pickerAttempt

	if isKDE() {
		attempts = append(attempts,
			pickerAttempt{"kdialog", kdialogOpenArgs(cfg, startDir)},
			pickerAttempt{"yad", yadOpenArgs(cfg, startDir, false)},
			pickerAttempt{"zenity", zenityOpenArgs(cfg, startDir)},
			pickerAttempt{"qarma", qarmaOpenArgs(cfg, startDir)},
		)
	} else {
		attempts = append(attempts,
			pickerAttempt{"zenity", zenityOpenArgs(cfg, startDir)},
			pickerAttempt{"yad", yadOpenArgs(cfg, startDir, false)},
			pickerAttempt{"kdialog", kdialogOpenArgs(cfg, startDir)},
			pickerAttempt{"qarma", qarmaOpenArgs(cfg, startDir)},
		)
	}

	var lastErr error
	for _, attempt := range attempts {
		selected, err := runPickerCommand(attempt.name, attempt.args...)
		if err == nil {
			return selected, nil
		}
		if errors.Is(err, errPickerCanceled) {
			return "", err
		}
		lastErr = err
	}

	hint := "instala kde-cli-tools (kdialog), zenity ou yad"
	if isKDE() {
		hint = "instala kde-cli-tools (pacman -S kde-cli-tools) para o diálogo nativo KDE, ou zenity/yad"
	}
	if lastErr != nil {
		return "", fmt.Errorf("file picker indisponível (%s): %w", hint, lastErr)
	}
	return "", fmt.Errorf("file picker indisponível (%s)", hint)
}

func pickSaveFileLinux(cfg FilePickerConfig) (string, error) {
	startPath := filepath.Join(cfg.DefaultDir, cfg.SaveAs)
	var attempts []pickerAttempt

	if isKDE() {
		attempts = append(attempts,
			pickerAttempt{"kdialog", kdialogSaveArgs(cfg, startPath)},
			pickerAttempt{"yad", yadOpenArgs(cfg, startPath, true)},
			pickerAttempt{"zenity", zenitySaveArgs(cfg, startPath)},
		)
	} else {
		attempts = append(attempts,
			pickerAttempt{"zenity", zenitySaveArgs(cfg, startPath)},
			pickerAttempt{"yad", yadOpenArgs(cfg, startPath, true)},
			pickerAttempt{"kdialog", kdialogSaveArgs(cfg, startPath)},
		)
	}

	var lastErr error
	for _, attempt := range attempts {
		selected, err := runPickerCommand(attempt.name, attempt.args...)
		if err == nil {
			return selected, nil
		}
		if errors.Is(err, errPickerCanceled) {
			return "", err
		}
		lastErr = err
	}
	if lastErr != nil {
		return "", fmt.Errorf("save dialog indisponível: %w", lastErr)
	}
	return "", fmt.Errorf("save dialog indisponível (instala zenity, yad ou kde-cli-tools)")
}

type pickerAttempt struct {
	name string
	args []string
}

func runPickerCommand(name string, args ...string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	cmd := exec.Command(path, args...)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return "", errPickerCanceled
		}
		return "", fmt.Errorf("%s: %w", name, err)
	}
	selected := strings.TrimSpace(string(out))
	if selected == "" {
		return "", errPickerCanceled
	}
	return selected, nil
}

func kdialogOpenArgs(cfg FilePickerConfig, startDir string) []string {
	filter := cfg.FileFilter
	if filter == "" {
		filter = "*"
	}
	return []string{"--getopenfilename", startDir, filter, "--title", cfg.Title}
}

func kdialogSaveArgs(cfg FilePickerConfig, startPath string) []string {
	filter := cfg.FileFilter
	if filter == "" {
		filter = "*"
	}
	return []string{"--getsavefilename", startPath, filter, "--title", cfg.Title}
}

func zenityOpenArgs(cfg FilePickerConfig, startDir string) []string {
	args := []string{"--file-selection", "--title=" + cfg.Title, "--filename=" + startDir}
	if cfg.FileFilter != "" {
		args = append(args, "--file-filter="+cfg.FileFilter)
	}
	return args
}

func zenitySaveArgs(cfg FilePickerConfig, startPath string) []string {
	return []string{"--file-selection", "--save", "--title=" + cfg.Title, "--filename=" + startPath}
}

func yadOpenArgs(cfg FilePickerConfig, startPath string, save bool) []string {
	args := []string{"--file", "--title=" + cfg.Title, "--filename=" + startPath}
	if save {
		args = append(args, "--save")
	}
	if cfg.FileFilter != "" {
		args = append(args, "--file-filter="+cfg.FileFilter)
	}
	return args
}

func qarmaOpenArgs(cfg FilePickerConfig, startDir string) []string {
	args := []string{"--file-selection", "--title=" + cfg.Title, "--filename=" + startDir}
	if cfg.FileFilter != "" {
		args = append(args, "--file-filter="+cfg.FileFilter)
	}
	return args
}

func escapePSSingleQuoted(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func escapeAppleScript(value string) string {
	return strings.ReplaceAll(value, `"`, `\"`)
}
