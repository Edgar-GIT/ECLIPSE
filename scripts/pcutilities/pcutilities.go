package pcutilities

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"programa/utils"
)

func PCUtilitiesMenu() {
	reader := bufio.NewReader(os.Stdin)
	for {
		utils.ClearTerminal()
		fmt.Printf("\n%s============ PC UTILITIES ============%s\n\n", utils.Blue, utils.Reset)
		fmt.Printf("%s[1]  - System information (advanced + export)%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[2]  - Open reports folder%s\n", utils.Green, utils.Reset)
		utils.PrintReturnOption("3")
		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if err != nil && line == "" {
			return
		}
		switch line {
		case "1":
			runSystemReportFlow(reader)
		case "2":
			openReportsFolder(reader)
		case "3":
			return
		default:
			fmt.Printf("%sInvalid option.%s\n", utils.Yellow, utils.Reset)
			utils.WaitForEnter(reader)
		}
	}
}

func runSystemReportFlow(reader *bufio.Reader) {
	utils.ClearTerminal()
	r, err := CollectSystemReport()
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", utils.Red, err, utils.Reset)
		utils.WaitForEnter(reader)
		return
	}

	fmt.Print(RenderReportText(r, true))

	fmt.Printf("\n%sExportar relatório para target/pc_reports (.txt + .html)? [Y/n]: %s", utils.Yellow, utils.Reset)
	if !promptYesNo(reader, true) {
		return
	}

	_, htmlPath, ex := ExportReportFiles(r)
	if ex != nil {
		fmt.Printf("%s[!] Export failed: %v%s\n", utils.Red, ex, utils.Reset)
		utils.WaitForEnter(reader)
		return
	}

	txtPath := strings.TrimSuffix(htmlPath, ".html") + ".txt"
	fmt.Printf("%s[✓] Relatório guardado:%s\n", utils.Green, utils.Reset)
	fmt.Printf("  %s\n  %s\n", txtPath, htmlPath)

	fmt.Printf("\n%sAbrir relatório HTML no browser? [Y/n]: %s", utils.Yellow, utils.Reset)
	if !promptYesNo(reader, true) {
		return
	}

	if err := utils.OpenLocalHTML(htmlPath); err != nil {
		fmt.Printf("%s[!] Não foi possível abrir no browser: %v%s\n", utils.Red, err, utils.Reset)
		utils.WaitForEnter(reader)
		return
	}

	fmt.Printf("%s[✓] Pedido enviado ao browser.%s\n", utils.Green, utils.Reset)
	time.Sleep(800 * time.Millisecond)
}

func openReportsFolder(reader *bufio.Reader) {
	dir := pathPCReportsDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Printf("%s[!] %v%s\n", utils.Red, err, utils.Reset)
		utils.WaitForEnter(reader)
		return
	}
	if err := utils.OpenLocalFile(dir); err != nil {
		fmt.Printf("%s[!] Não foi possível abrir a pasta: %v%s\n", utils.Red, err, utils.Reset)
		fmt.Printf("%sCaminho: %s%s\n", utils.Yellow, dir, utils.Reset)
		utils.WaitForEnter(reader)
		return
	}
	fmt.Printf("%s[✓] Pasta aberta: %s%s\n", utils.Green, dir, utils.Reset)
	time.Sleep(600 * time.Millisecond)
}

func promptYesNo(reader *bufio.Reader, defaultYes bool) bool {
	ans, _ := reader.ReadString('\n')
	ans = strings.ToLower(strings.TrimSpace(ans))
	if ans == "" {
		return defaultYes
	}
	return ans == "y" || ans == "yes" || ans == "s" || ans == "sim"
}
