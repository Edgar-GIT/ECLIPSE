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
		fmt.Printf("%s[1]  - System information (advanced)%s\n", utils.Green, utils.Reset)
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
			PrintAdvancedSystemReport()
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
