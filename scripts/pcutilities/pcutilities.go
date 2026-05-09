package pcutilities

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"programa/utils"
)

func PCUtilitiesMenu() {
	reader := bufio.NewReader(os.Stdin)
	for {
		utils.ClearTerminal()
		fmt.Printf("\n%s============ PC UTILITIES ============%s\n\n", utils.Blue, utils.Reset)
		fmt.Printf("%s[1]  - System information (advanced + export)%s\n", utils.Green, utils.Reset)
		utils.PrintReturnOption("2")
		fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if err != nil && line == "" {
			return
		}
		switch line {
		case "1":
			utils.ClearTerminal()
			r, err := CollectSystemReport()
			if err != nil {
				fmt.Printf("%s[!] %v%s\n", utils.Red, err, utils.Reset)
				utils.WaitForEnter(reader)
				continue
			}
			fmt.Print(RenderReportText(r, true))
			fmt.Printf("\n%sExport report to target/pc_reports (.txt + .html)? [Y/n]: %s", utils.Yellow, utils.Reset)
			ans, _ := reader.ReadString('\n')
			ans = strings.ToLower(strings.TrimSpace(ans))
			if ans == "" || ans == "y" || ans == "yes" {
				tp, hp, ex := ExportReportFiles(r)
				if ex != nil {
					fmt.Printf("%s[!] Export failed: %v%s\n", utils.Red, ex, utils.Reset)
				} else {
					fmt.Printf("%sSaved:%s\n  %s\n  %s\n", utils.Green, utils.Reset, tp, hp)
				}
			}
			fmt.Printf("\n%sPress Enter to continue...%s", utils.Green, utils.Reset)
			reader.ReadString('\n')
		case "2":
			return
		default:
			fmt.Printf("%sInvalid option.%s\n", utils.Yellow, utils.Reset)
			utils.WaitForEnter(reader)
		}
	}
}
