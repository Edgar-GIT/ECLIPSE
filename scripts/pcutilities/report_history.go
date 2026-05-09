package pcutilities

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"programa/utils"
)

func ViewPCReportHistory() {
	reader := bufio.NewReader(os.Stdin)
	dir := pathPCReportsDir()
	for {
		utils.ClearTerminal()
		fmt.Printf("\n%s╔════════════════════════════════════════════════════════════════╗%s\n", utils.Purple, utils.Reset)
		fmt.Printf("%s║         PC SYSTEM REPORTS — ficheiros exportados            ║%s\n", utils.Purple, utils.Reset)
		fmt.Printf("%s╚════════════════════════════════════════════════════════════════╝%s\n\n", utils.Purple, utils.Reset)

		entries, err := listReportFiles(dir)
		if err != nil {
			fmt.Printf("%s[!] %v%s\n", utils.Red, err, utils.Reset)
			utils.WaitForEnter(reader)
			return
		}
		if len(entries) == 0 {
			fmt.Printf("%sNenhum relatório guardado. Usa PC Utilities → exportar.%s\n\n", utils.Yellow, utils.Reset)
			fmt.Printf("%s[0]  Voltar ao menu History%s\n", utils.Green, utils.Reset)
			fmt.Printf("\n%sOpção: %s", utils.Green, utils.Reset)
			line, _ := reader.ReadString('\n')
			if strings.TrimSpace(line) == "0" {
				return
			}
			continue
		}

		sort.Slice(entries, func(i, j int) bool { return entries[i].name > entries[j].name })
		for i, e := range entries {
			tag := "[TXT]"
			if strings.HasSuffix(strings.ToLower(e.name), ".html") {
				tag = "[HTML · browser]"
			}
			fmt.Printf("%s[%2d]%s %s  %s\n", utils.Green, i+1, utils.Reset, tag, e.name)
		}

		fmt.Printf("\n%s──────── Navegação ────────%s\n", utils.Blue, utils.Reset)
		fmt.Printf("%s[0]  Voltar ao menu History (sair desta lista)%s\n", utils.Yellow, utils.Reset)
		fmt.Printf("%s[#]  Abrir relatório pelo número%s\n", utils.Blue, utils.Reset)
		fmt.Printf("\n%sEscolhe opção: %s", utils.Green, utils.Reset)
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" || line == "0" {
			return
		}
		var n int
		if _, err := fmt.Sscanf(line, "%d", &n); err != nil || n < 1 || n > len(entries) {
			fmt.Printf("%sOpção inválida.%s\n", utils.Yellow, utils.Reset)
			utils.WaitForEnter(reader)
			continue
		}

		path := filepath.Join(dir, entries[n-1].name)
		base := entries[n-1].name
		openReportFile(path, base)

		for {
			utils.ClearTerminal()
			fmt.Printf("\n%s── Relatório: %s ──%s\n\n", utils.Blue, base, utils.Reset)
			if strings.HasSuffix(strings.ToLower(base), ".html") {
				fmt.Printf("%sAberto no browser (gráficos HTML).%s\n\n", utils.Green, utils.Reset)
			}
			fmt.Printf("%s[Enter]  Voltar à lista de reports%s\n", utils.Green, utils.Reset)
			fmt.Printf("%s[0]      Voltar ao menu History%s\n", utils.Yellow, utils.Reset)
			fmt.Printf("%s[R]      Reabrir este ficheiro%s\n", utils.Blue, utils.Reset)
			fmt.Printf("\n%sOpção: %s", utils.Green, utils.Reset)
			sub, _ := reader.ReadString('\n')
			sub = strings.TrimSpace(strings.ToLower(sub))
			if sub == "0" {
				return
			}
			if sub == "r" {
				openReportFile(path, base)
				continue
			}
			break
		}
	}
}

type reportEntry struct {
	name string
}

func listReportFiles(dir string) ([]reportEntry, error) {
	d, err := os.Open(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []reportEntry{}, nil
		}
		return nil, err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	var out []reportEntry
	for _, name := range names {
		if strings.HasSuffix(name, ".txt") || strings.HasSuffix(name, ".html") {
			out = append(out, reportEntry{name: name})
		}
	}
	return out, nil
}

func openReportFile(fullPath, base string) {
	utils.ClearTerminal()
	if strings.HasSuffix(strings.ToLower(base), ".html") {
		if runtime.GOOS == "windows" {
			if err := exec.Command("rundll32", "url.dll,FileProtocolHandler", fullPath).Start(); err == nil {
				fmt.Printf("%s%s%s\n", utils.Green, "Browser aberto com relatório animado (HTML).", utils.Reset)
				return
			}
		}
		for _, bin := range []string{"xdg-open", "open"} {
			cmd := exec.Command(bin, fullPath)
			if err := cmd.Start(); err == nil {
				fmt.Printf("%s%s%s\n", utils.Green, "Browser aberto com relatório animado (HTML).", utils.Reset)
				return
			}
		}
		fmt.Printf("%sNão foi possível abrir o browser. Abre manualmente:%s\n%s\n", utils.Yellow, utils.Reset, fullPath)
		return
	}
	b, err := os.ReadFile(fullPath)
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", utils.Red, err, utils.Reset)
		return
	}
	text := stripANSI(string(b))
	pagers := []string{"less", "more"}
	for _, p := range pagers {
		if lp, err := exec.LookPath(p); err == nil {
			args := []string{}
			if p == "less" {
				args = append(args, "-R", "-")
			}
			cmd := exec.Command(lp, args...)
			cmd.Stdin = strings.NewReader(text)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			_ = cmd.Run()
			return
		}
	}
	fmt.Print(text)
}
