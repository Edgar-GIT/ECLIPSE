package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"programa/scripts/garbageinjector"
	"programa/scripts/imganalysis"
	"programa/scripts/ipscanner"
	"programa/scripts/keylogger"
	"programa/scripts/nethunter"
	"programa/scripts/osint"
	"programa/scripts/portscanner"
	"programa/scripts/ransomware"
	"programa/utils"
)

func Menu() {
	leftPad := "        "
	gap := "  "
	intro := "The only multitool 🛠️  you will ever need - v1.0.0 - https://github.com/Edgar-GIT"
	title := "TOOLS"

	col1 := []string{
		"[1]  - IP Scanner",
		"[2]  - Port Scanner",
		"[3]  - OSINT",
		"[4]  - PC Utilities",
		"[5]  - DNS/REVERSE DNS",
		"[6]  - OSINT Statistics",
		"[7]  - View Computer Report",
		"[8]  - View Scan Results (ip)",
		"[9]  - View Port Scan Results",
		"[10] - View Website Report",
	}
	col2 := []string{
		"[11] - Password Cracker",
		"[12] - DoS",
		"[13] - Image Analysis",
		"[14] - View Image History",
		"[15] - NetHunter",
		"[16] - Cookie Grabber",
		"[17] - Car Information",
		"[18] - Phone Information",
		"[19] - ZPHISHER",
		"[20] - Sub Domain Finder",
	}
	col3 := []string{
		"[21] - RAT",
		"[22] - Ransomware",
		"[23] - Keylogger",
		"[24] - Garbage Injector",
		"[25] - Live Camera Hijack",
		"[26] - Evil QR",
		"[27] - ",
		"[28] - ",
		"[29] - ",
		"[30] - ",
	}

	boxWidth := 30
	boxes := [][]string{
		utils.MakeBoxLines(col1, boxWidth),
		utils.MakeBoxLines(col2, boxWidth),
		utils.MakeBoxLines(col3, boxWidth),
	}

	blue := [3]int{70, 92, 250}
	indigo := [3]int{94, 88, 255}
	violet := [3]int{180, 82, 255}

	totalWidth := (boxWidth + 4) * 3
	titlePadding := (totalWidth - len(title)) / 2

	fmt.Printf("\n%s%s%s\n\n", leftPad, utils.RGBText(255, 210, 60, intro), utils.Reset)
	fmt.Printf("%s%s%s\n\n", leftPad, utils.RGBText(97, 114, 255, strings.Repeat(" ", titlePadding)+title), utils.Reset)

	for i := range boxes[0] {
		fmt.Printf("%s%s%s%s%s%s%s\n",
			leftPad,
			utils.RGBText(blue[0], blue[1], blue[2], boxes[0][i]),
			gap,
			utils.RGBText(indigo[0], indigo[1], indigo[2], boxes[1][i]),
			gap,
			utils.RGBText(violet[0], violet[1], violet[2], boxes[2][i]),
			utils.Reset,
		)
	}

	fmt.Println()
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	for {
		utils.ClearTerminal()
		utils.Banner()
		Menu()

		fmt.Printf("%sChoose a Tool (q to quit): %s", utils.Green, utils.Reset)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if strings.ToLower(input) == "q" {
			fmt.Printf("%sLeaving... Stay Ethical!!%s\n", utils.Yellow, utils.Reset)
			os.Exit(0)
		}

		switch input {
		case "1":
			ipscanner.IpScanner()
		case "2":
			portscanner.PortScanner()
		case "3":
			osint.OSINTToolkit()
		case "13":
			imganalysis.ImageAnalysis()
		case "15":
			nethunter.NetHunter()
		case "23":
			keylogger.LaunchKeylogger()
		case "24":
			garbageinjector.GarbageInjector()
		case "22":
			ransomware.LaunchRansomware()
		default:
			fmt.Printf("%sInvalid option!%s\n", utils.Yellow, utils.Reset)
			fmt.Printf("\n%sPress Enter to continue...%s", utils.Green, utils.Reset)
			reader.ReadString('\n')
		}
	}
}
