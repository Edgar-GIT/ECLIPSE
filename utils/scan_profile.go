package utils

import (
	"bufio"
	"fmt"
	"strings"
)

// PromptScanProfile asks how to configure scan intensity.
// Returns profile: fast, medium, full, custom; ok false if user cancels.
func PromptScanProfile(reader *bufio.Reader) (profile string, ok bool) {
	fmt.Printf("\n%s── Perfil de scan ──%s\n", Blue, Reset)
	fmt.Printf("%s[1] Fast   — portas/métodos comuns, timing moderado (default)%s\n", Green, Reset)
	fmt.Printf("%s[2] Medium — mais probes, T4, maior paralelismo%s\n", Green, Reset)
	fmt.Printf("%s[3] Full   — máximo desempenho (T5, tudo o que for possível)%s\n", Green, Reset)
	fmt.Printf("%s[4] Custom — inserir flags manualmente%s\n", Green, Reset)
	fmt.Printf("%s[0] Cancelar%s\n", Yellow, Reset)
	fmt.Printf("\n%sEscolhe perfil: %s", Green, Reset)

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
