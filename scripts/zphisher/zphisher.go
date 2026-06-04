package zphisher

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"programa/utils"
)

// Launch ensures Zphisher is available under exec_tools and runs it in the foreground.
func Launch() {
	reader := bufio.NewReader(os.Stdin)
	utils.ClearTerminal()
	fmt.Printf("\n%s=== ZPHISHER ===%s\n", utils.Blue, utils.Reset)
	fmt.Printf("%sEducational phishing framework · upstream: %s%s\n\n", utils.Yellow, repoURL, utils.Reset)

	if err := ensureZphisher(reader); err != nil {
		fmt.Printf("%s[!] %v%s\n", utils.Red, err, utils.Reset)
		utils.WaitForEnter(reader)
		return
	}

	bash, err := resolveBash()
	if err != nil {
		fmt.Printf("%s[!] %v%s\n", utils.Red, err, utils.Reset)
		printDependencyHints()
		utils.WaitForEnter(reader)
		return
	}

	dir := zphisherDir()
	fmt.Printf("%s[*] A iniciar Zphisher (Ctrl+C para interromper)...%s\n\n", utils.Green, utils.Reset)

	cmd := exec.Command(bash, "zphisher.sh")
	cmd.Dir = dir
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			fmt.Printf("\n%s[*] Zphisher terminou.%s\n", utils.Yellow, utils.Reset)
		} else {
			fmt.Printf("\n%s[!] Execução falhou: %v%s\n", utils.Red, err, utils.Reset)
		}
	}

	fmt.Printf("\n%sPress Enter to voltar ao menu...%s", utils.Green, utils.Reset)
	reader.ReadString('\n')
}

func ensureZphisher(reader *bufio.Reader) error {
	if fileExists(zphisherScript()) {
		return ensureRuntimeDeps()
	}

	dir := zphisherDir()
	if dirExists(dir) && !canBootstrapRepo(dir) {
		return fmt.Errorf("%s existe mas falta zphisher.sh — apaga a pasta ou corre: git clone --depth=1 %s %s",
			dir, repoURL, dir)
	}

	fmt.Printf("%sZphisher não está instalado em %s%s\n", utils.Yellow, dir, utils.Reset)
	if !promptYesNo(reader, "Descarregar agora com git clone?") {
		return fmt.Errorf("instalação cancelada")
	}

	if err := ensureDependency("git"); err != nil {
		return err
	}

	if dirExists(dir) && canBootstrapRepo(dir) {
		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("não foi possível preparar %s: %w", dir, err)
		}
	}

	if err := os.MkdirAll(execToolsDir(), 0755); err != nil {
		return err
	}

	gitPath, err := exec.LookPath("git")
	if err != nil {
		return fmt.Errorf("git não encontrado no PATH")
	}

	fmt.Printf("%s[*] A clonar %s ...%s\n", utils.Blue, repoURL, utils.Reset)
	cmd := exec.Command(gitPath, "clone", "--depth=1", repoURL, dir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone falhou: %w", err)
	}

	if !fileExists(zphisherScript()) {
		return fmt.Errorf("clone concluído mas %s não encontrado", zphisherScript())
	}

	fmt.Printf("%s[✓] Zphisher instalado em %s%s\n", utils.Green, dir, utils.Reset)
	return ensureRuntimeDeps()
}

func ensureRuntimeDeps() error {
	for _, dep := range []string{"curl", "php"} {
		if err := ensureDependency(dep); err != nil {
			return err
		}
	}
	if _, err := resolveBash(); err != nil {
		return err
	}
	return nil
}

func ensureDependency(name string) error {
	if _, err := exec.LookPath(name); err == nil {
		return nil
	}
	return fmt.Errorf("dependência em falta: %s (o Zphisher instala mais na primeira execução)", name)
}

func resolveBash() (string, error) {
	candidates := []string{"bash", "sh"}
	if runtime.GOOS == "windows" {
		candidates = append([]string{
			`C:\Program Files\Git\bin\bash.exe`,
			`C:\Program Files (x86)\Git\bin\bash.exe`,
		}, candidates...)
	}
	for _, c := range candidates {
		if strings.Contains(c, string(os.PathSeparator)) {
			if fileExists(c) {
				return c, nil
			}
			continue
		}
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("bash não encontrado (Linux: bash; Windows: Git Bash)")
}

func canBootstrapRepo(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	if len(entries) == 0 {
		return true
	}
	for _, e := range entries {
		name := e.Name()
		switch name {
		case "README.md", "LICENSE", ".gitkeep":
			continue
		default:
			return false
		}
	}
	return true
}

func promptYesNo(reader *bufio.Reader, question string) bool {
	fmt.Printf("%s%s (y/N): %s", utils.Yellow, question, utils.Reset)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "y" || answer == "yes" || answer == "s" || answer == "sim"
}

func printDependencyHints() {
	fmt.Printf("\n%sDependências (Arch exemplo):%s\n", utils.Blue, utils.Reset)
	fmt.Printf("  sudo pacman -S git curl php bash\n")
	fmt.Printf("%sManual:%s cd %s && bash zphisher.sh\n\n", utils.Blue, utils.Reset, zphisherDir())
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
