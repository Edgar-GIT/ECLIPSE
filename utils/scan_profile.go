package utils

import (
	"bufio"
	"fmt"
	"strings"
)

func PromptScanProfile(reader *bufio.Reader) (profile string, ok bool) {
	fmt.Printf("\n%s── Perfil de scan ──%s\n", Blue, Reset)
	fmt.Printf("%s[1] Fast   — common ports/methods, moderate timing (default)%s\n", Green, Reset)
	fmt.Printf("%s[2] Medium — more probes, T4, more concurrency%s\n", Green, Reset)
	fmt.Printf("%s[3] Full   — maximum performance%s\n", Green, Reset)
	fmt.Printf("%s[4] Custom — insert flags manually%s\n", Green, Reset)
	fmt.Printf("%s[0] Cancel%s\n", Yellow, Reset)
	fmt.Printf("\n%sChoose a Profile: %s", Green, Reset)

	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	switch line {
	case "1", "fast", "f":
		return "fast", true
	case "2", "medium", "med", "m":
		return "medium", true
	case "3", "full", "max":
		return "full", true
	case "4", "custom", "flags", "c":
		return "custom", true
	case "0", "":
		return "", false
	default:
		fmt.Printf("%sOpção inválida.%s\n", Yellow, Reset)
		return "", false
	}
}
