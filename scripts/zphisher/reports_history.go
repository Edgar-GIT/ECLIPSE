package zphisher

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"programa/scripts/reportsdir"
	"programa/utils"
)

func ViewZphisherReports() {
	reader := bufio.NewReader(os.Stdin)
	for {
		utils.ClearTerminal()
		fmt.Printf("\n%s=== ZPHISHER REPORTS ===%s\n", utils.Blue, utils.Reset)
		fmt.Printf("%sCapturas em:%s %s\n", utils.Green, utils.Reset, reportsdir.ZphisherAuth())
		fmt.Printf("%sSessões arquivadas:%s %s\n\n", utils.Green, utils.Reset, reportsdir.ZphisherSessions())

		sessions, _ := listSessionDirs()
		if len(sessions) == 0 {
			fmt.Printf("%sNenhuma sessão arquivada ainda. Corre o Zphisher (opção 12) e guarda capturas.%s\n\n", utils.Yellow, utils.Reset)
		} else {
			sort.Strings(sessions)
			for i := len(sessions) - 1; i >= 0; i-- {
				fmt.Printf("%s[%d]%s %s\n", utils.Green, len(sessions)-i, utils.Reset, sessions[i])
			}
		}

		fmt.Printf("\n%s[1] Ver capturas atuais (auth/)%s\n", utils.Green, utils.Reset)
		if len(sessions) > 0 {
			fmt.Printf("%s[#] Ver sessão pelo número%s\n", utils.Green, utils.Reset)
		}
		fmt.Printf("%s[2] Abrir pasta reports/zphisher%s\n", utils.Green, utils.Reset)
		fmt.Printf("%s[0] Voltar%s\n", utils.Yellow, utils.Reset)
		fmt.Printf("\n%sOpção: %s", utils.Green, utils.Reset)

		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" || line == "0" {
			return
		}
		if line == "1" {
			showCaptureDir(reader, reportsdir.ZphisherAuth())
			continue
		}
		if line == "2" {
			_ = utils.OpenLocalFile(reportsdir.Zphisher())
			continue
		}
		var n int
		if _, err := fmt.Sscanf(line, "%d", &n); err == nil && n >= 1 && n <= len(sessions) {
			idx := len(sessions) - n
			showCaptureDir(reader, filepath.Join(reportsdir.ZphisherSessions(), sessions[idx]))
			continue
		}
		fmt.Printf("%sOpção inválida.%s\n", utils.Yellow, utils.Reset)
		utils.WaitForEnter(reader)
	}
}

func listSessionDirs() ([]string, error) {
	root := reportsdir.ZphisherSessions()
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

func showCaptureDir(reader *bufio.Reader, dir string) {
	utils.ClearTerminal()
	fmt.Printf("\n%s── %s ──%s\n\n", utils.Blue, dir, utils.Reset)

	for _, name := range []string{authIPFile, authCredsFile, "README.txt"} {
		path := filepath.Join(dir, name)
		if !fileExists(path) {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("%s[!] %s: %v%s\n", utils.Red, name, err, utils.Reset)
			continue
		}
		fmt.Printf("%s--- %s ---%s\n", utils.Yellow, name, utils.Reset)
		fmt.Printf("%s%s%s\n\n", utils.Blue, string(raw), utils.Reset)
	}

	if !hasAnyCapture(dir) {
		fmt.Printf("%s(Sem ficheiros de captura nesta pasta.)%s\n", utils.Yellow, utils.Reset)
	}
	utils.WaitForEnter(reader)
}

func hasAnyCapture(dir string) bool {
	for _, name := range []string{authIPFile, authCredsFile} {
		if fileExists(filepath.Join(dir, name)) {
			return true
		}
	}
	return false
}
