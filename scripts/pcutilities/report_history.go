package pcutilities

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
		fmt.Printf("%s[0]  Voltar ao menu History%s\n", utils.Yellow, utils.Reset)
		fmt.Printf("%s[#]  Abrir relatório pelo número%s\n", utils.Blue, utils.Reset)
		fmt.Printf("%s[D]  Eliminar um relatório pelo número%s\n", utils.Red, utils.Reset)
		fmt.Printf("\n%sEscolhe opção: %s", utils.Green, utils.Reset)
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" || line == "0" {
			return
		}
		if strings.EqualFold(line, "d") {
			promptDeleteReport(reader, dir, entries)
			continue
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
				fmt.Printf("%sSe o browser não abriu, usa [R] ou: xdg-open <caminho abaixo>%s\n\n", utils.Yellow, utils.Reset)
			}
			abs, _ := filepath.Abs(path)
			fmt.Printf("%s\n\n", utils.RGBText(120, 130, 160, abs))
			fmt.Printf("%s[Enter]  Voltar à lista de reports%s\n", utils.Green, utils.Reset)
			fmt.Printf("%s[0]      Voltar ao menu History%s\n", utils.Yellow, utils.Reset)
			fmt.Printf("%s[R]      Reabrir no browser%s\n", utils.Blue, utils.Reset)
			fmt.Printf("%s[X]      Eliminar este ficheiro%s\n", utils.Red, utils.Reset)
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
			if sub == "x" {
				if confirmDelete(reader, path, base) {
					_ = os.Remove(path)
					pair := pairedExportName(base)
					if pair != "" {
						_ = os.Remove(filepath.Join(dir, pair))
					}
					fmt.Printf("%sEliminado.%s\n", utils.Green, utils.Reset)
					utils.WaitForEnter(reader)
				}
				break
			}
			break
		}
	}
}

func pairedExportName(base string) string {
	stem := strings.TrimSuffix(strings.TrimSuffix(base, ".html"), ".txt")
	if stem == base {
		return ""
	}
	if strings.HasSuffix(strings.ToLower(base), ".html") {
		return stem + ".txt"
	}
	return stem + ".html"
}

func promptDeleteReport(reader *bufio.Reader, dir string, entries []reportEntry) {
	fmt.Printf("%sNúmero do relatório a eliminar (0=cancelar): %s", utils.Red, utils.Reset)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	var n int
	if _, err := fmt.Sscanf(line, "%d", &n); err != nil || n < 1 || n > len(entries) {
		return
	}
	path := filepath.Join(dir, entries[n-1].name)
	if !confirmDelete(reader, path, entries[n-1].name) {
		return
	}
	_ = os.Remove(path)
	if p := pairedExportName(entries[n-1].name); p != "" {
		_ = os.Remove(filepath.Join(dir, p))
	}
	fmt.Printf("%sFicheiro(s) eliminado(s).%s\n", utils.Green, utils.Reset)
	utils.WaitForEnter(reader)
}

func confirmDelete(reader *bufio.Reader, path, label string) bool {
	fmt.Printf("%sEliminar %s ? [s/N]: %s", utils.Yellow, label, utils.Reset)
	ans, _ := reader.ReadString('\n')
	ans = strings.TrimSpace(strings.ToLower(ans))
	return ans == "s" || ans == "sim" || ans == "y" || ans == "yes"
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
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		absPath = fullPath
	}
	if _, err := os.Stat(absPath); err != nil {
		fmt.Printf("%s[!] Ficheiro não encontrado: %v%s\n", utils.Red, err, utils.Reset)
		return
	}
	if strings.HasSuffix(strings.ToLower(base), ".html") {
		if err := utils.OpenLocalHTML(absPath); err != nil {
			fmt.Printf("%s[!] Abrir HTML: %v%s\n", utils.Red, err, utils.Reset)
			fmt.Printf("%sTenta: xdg-open %q%s\n", utils.Yellow, absPath, utils.Reset)
		} else {
			fmt.Printf("%sPedido enviado ao browser predefinido.%s\n", utils.Green, utils.Reset)
		}
		return
	}
	b, err := os.ReadFile(absPath)
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
