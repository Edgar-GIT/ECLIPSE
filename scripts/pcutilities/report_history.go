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
		fmt.Printf("\n%s============ PC SYSTEM REPORTS ============%s\n\n", utils.Blue, utils.Reset)
		entries, err := listReportFiles(dir)
		if err != nil {
			fmt.Printf("%s[!] %v%s\n", utils.Red, err, utils.Reset)
			utils.WaitForEnter(reader)
			return
		}
		if len(entries) == 0 {
			fmt.Printf("%sNo saved reports yet. Run PC Utilities and export a report.%s\n", utils.Yellow, utils.Reset)
			utils.PrintReturnOption("0")
			fmt.Printf("\n%sOption: %s", utils.Green, utils.Reset)
			line, _ := reader.ReadString('\n')
			if strings.TrimSpace(line) == "0" {
				return
			}
			continue
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].name > entries[j].name })
		for i, e := range entries {
			fmt.Printf("%s[%d]%s %s\n", utils.Green, i+1, utils.Reset, e.name)
		}
		fmt.Printf("\n%s[0] Return%s\n", utils.Yellow, utils.Reset)
		fmt.Printf("\n%sOpen report # (txt via pager if available): %s", utils.Green, utils.Reset)
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" || line == "0" {
			return
		}
		var n int
		fmt.Sscanf(line, "%d", &n)
		if n < 1 || n > len(entries) {
			fmt.Printf("%sInvalid.%s\n", utils.Yellow, utils.Reset)
			utils.WaitForEnter(reader)
			continue
		}
		path := filepath.Join(dir, entries[n-1].name)
		openReportFile(path, entries[n-1].name)
		fmt.Printf("\n%sPress Enter...%s", utils.Green, utils.Reset)
		reader.ReadString('\n')
	}
}

type reportEntry struct {
	name string
}

func listReportFiles(dir string) ([]reportEntry, error) {
	d, err := os.Open(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
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
	if strings.HasSuffix(base, ".html") {
		if runtime.GOOS == "windows" {
			if err := exec.Command("rundll32", "url.dll,FileProtocolHandler", fullPath).Start(); err == nil {
				fmt.Printf("%sOpened in default browser.%s\n", utils.Green, utils.Reset)
				return
			}
		}
		for _, bin := range []string{"xdg-open", "open"} {
			cmd := exec.Command(bin, fullPath)
			if err := cmd.Start(); err == nil {
				fmt.Printf("%sOpened in browser / default app.%s\n", utils.Green, utils.Reset)
				return
			}
		}
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
