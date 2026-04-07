package utils

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

const (
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Purple = "\033[35m"
	Green  = "\033[32m"
	Red    = "\033[31m"
	Reset  = "\033[0m"
)

// Discord Configuration
var (
	DiscordBotToken string
	DiscordGuildID  string

	discordConfigOnce sync.Once
	discordConfigErr  error
)

func DetectOS() string {
	return runtime.GOOS
}

func ClearTerminal() {
	if DetectOS() == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

func Banner() {
	fmt.Println()
	fmt.Println()
	fmt.Println()
	const nightBanner = `
__/\\\\\\\\\\\\\\\________________/\\\\\\____________________________________________________
 _\/\\\///////////________________\////\\\____________________________________________________
  _\/\\\______________________________\/\\\_____/\\\___/\\\\\\\\\______________________________
   _\/\\\\\\\\\\\_________/\\\\\\\\____\/\\\____\///___/\\\/////\\\__/\\\\\\\\\\_____/\\\\\\\\__
    _\/\\\///////________/\\\//////_____\/\\\_____/\\\_\/\\\\\\\\\\__\/\\\//////____/\\\/////\\\_
     _\/\\\______________/\\\____________\/\\\____\/\\\_\/\\\//////___\/\\\\\\\\\\__/\\\\\\\\\\\__
      _\/\\\_____________\//\\\___________\/\\\____\/\\\_\/\\\_________\////////\\\_\//\\///////___
       _\/\\\\\\\\\\\\\\\__\///\\\\\\\\__/\\\\\\\\\_\/\\\_\/\\\__________/\\\\\\\\\\__\//\\\\\\\\\\_
        _\///////////////_____\////////__\/////////__\///__\///__________\//////////____\//////////__
`

	palette := [][3]int{
		{14, 20, 50},   // very dark blue
		{34, 42, 92},   // night blue
		{70, 52, 128},  // indigo
		{106, 72, 170}, // purple
		{56, 106, 188}, // cool blue
	}

	lerp := func(a, b int, t float64) int {
		return int(float64(a) + (float64(b-a) * t))
	}

	gradientColor := func(t float64) (int, int, int) {
		if t <= 0 {
			return palette[0][0], palette[0][1], palette[0][2]
		}
		if t >= 1 {
			last := palette[len(palette)-1]
			return last[0], last[1], last[2]
		}

		segments := len(palette) - 1
		pos := t * float64(segments)
		idx := int(pos)
		if idx >= segments {
			idx = segments - 1
		}
		localT := pos - float64(idx)

		c1 := palette[idx]
		c2 := palette[idx+1]
		return lerp(c1[0], c2[0], localT), lerp(c1[1], c2[1], localT), lerp(c1[2], c2[2], localT)
	}

	lines := strings.Split(strings.Trim(nightBanner, "\n"), "\n")
	for i, line := range lines {
		var t float64
		if len(lines) > 1 {
			t = float64(i) / float64(len(lines)-1)
		}
		r, g, b := gradientColor(t)
		fmt.Printf("\033[38;2;%d;%d;%dm%s%s\n", r, g, b, line, Reset)
	}
}

func RGBText(r, g, b int, value string) string {
	return fmt.Sprintf("\033[38;2;%d;%d;%dm%s%s", r, g, b, value, Reset)
}

func PadOrTrim(value string, width int) string {
	runes := []rune(value)
	if len(runes) > width {
		return string(runes[:width])
	}
	return value + strings.Repeat(" ", width-len(runes))
}

func MakeBoxLines(items []string, width int) []string {
	lines := make([]string, 0, len(items)+2)
	border := strings.Repeat("─", width+2)
	lines = append(lines, fmt.Sprintf("╭%s╮", border))
	for _, item := range items {
		lines = append(lines, fmt.Sprintf("│ %s │", PadOrTrim(item, width)))
	}
	lines = append(lines, fmt.Sprintf("╰%s╯", border))
	return lines
}

func MakeLabelBox(text string, width int) []string {
	border := strings.Repeat("─", width+2)
	return []string{
		fmt.Sprintf("╭%s╮", border),
		fmt.Sprintf("│ %s │", PadOrTrim(text, width)),
		fmt.Sprintf("╰%s╯", border),
	}
}

func PauseForInput() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("\n%sPress Enter to continue...%s", Green, Reset)
	reader.ReadString('\n')
}

func WaitForEnter(reader *bufio.Reader) {
	fmt.Printf("\n%sPress Enter to return to menu...%s", Green, Reset)
	reader.ReadString('\n')
}

func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "Unknown"
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "Unknown"
}

func GetMACAddress() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "Unknown"
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			mac := iface.HardwareAddr.String()
			if mac != "" {
				return mac
			}
		}
	}
	return "Unknown"
}

func IsValidIPv4(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	return parsed != nil && parsed.To4() != nil
}

// ============================================
// SYSTEM INFORMATION FUNCTIONS
// ============================================

// GetHostname retrieves the system hostname
func GetHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "Unknown"
	}
	return hostname
}

// GetOS returns the operating system and architecture
func GetOS() string {
	return runtime.GOOS + " " + runtime.GOARCH
}

// GetUsername retrieves the current username
func GetUsername() string {
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	if user == "" {
		return "Unknown"
	}
	return user
}

// ============================================
// STRING SANITIZATION FUNCTIONS
// ============================================

// SanitizeString removes non-printable characters
func SanitizeString(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}

	clean := strings.Map(func(r rune) rune {
		if r >= 32 && r <= 126 || r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		return -1
	}, string(raw))

	clean = strings.TrimSpace(clean)
	return clean
}

// SanitizeChannelName sanitizes a string for use as a Discord channel name
func SanitizeChannelName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, " ", "-")
	name = strings.ReplaceAll(name, ".", "-")
	name = strings.ReplaceAll(name, "_", "-")

	var result strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			result.WriteRune(r)
		}
	}

	final := result.String()
	if len(final) > 50 {
		final = final[:50]
	}

	return final
}

// SanitizeForFilename sanitizes a string for use as a filename
func SanitizeForFilename(v string) string {
	for _, ch := range []string{"<", ">", ":", "\"", "/", "\\", "|", "?", "*", "\x00"} {
		v = strings.ReplaceAll(v, ch, "_")
	}
	return v
}

// SanitizeLogName creates a safe name for log files
func SanitizeLogName(input string) string {
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, input)
	return safe
}

// ============================================
// FILE OPERATIONS
// ============================================

// CopyFile copies a file from src to dst
func CopyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, input, 0644)
}

// CopyFileWithPermissions copies a file with specific permissions
func CopyFileWithPermissions(src, dst string, perm os.FileMode) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, input, perm)
}

// ============================================
// DISCORD CONFIGURATION
// ============================================

// EnsureDiscordConfig ensures Discord bot credentials are configured
func EnsureDiscordConfig() error {
	discordConfigOnce.Do(func() {
		token := strings.TrimSpace(os.Getenv("DISCORD_BOT_TOKEN"))
		guild := strings.TrimSpace(os.Getenv("DISCORD_GUILD_ID"))

		reader := bufio.NewReader(os.Stdin)
		if token == "" {
			fmt.Print("Enter Discord bot token: ")
			input, _ := reader.ReadString('\n')
			token = strings.TrimSpace(input)
		}
		if guild == "" {
			fmt.Print("Enter Discord guild ID: ")
			input, _ := reader.ReadString('\n')
			guild = strings.TrimSpace(input)
		}

		if token == "" || guild == "" {
			discordConfigErr = fmt.Errorf("discord credentials missing (set DISCORD_BOT_TOKEN and DISCORD_GUILD_ID)")
			return
		}

		DiscordBotToken = token
		DiscordGuildID = guild
	})

	return discordConfigErr
}

// ============================================
// NETWORK UTILITIES
// ============================================

// GetHostnameFromIP attempts to get hostname from IP address
func GetHostnameFromIP(ip string) string {
	addrs, err := net.LookupAddr(ip)
	if err != nil {
		return ip
	}
	if len(addrs) > 0 {
		return strings.TrimSuffix(addrs[0], ".")
	}
	return ip
}

// ============================================
// COMMAND EXECUTION UTILITIES
// ============================================

// ExecuteCommand runs a shell command and returns output
func ExecuteCommand(command string) string {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Sprintf("Error: %v\n%s", err, string(output))
	}

	return string(output)
}

// ============================================
// MENU UTILITIES
// ============================================

// PrintReturnOption prints a styled "Return to Main Menu" option
func PrintReturnOption(optionNumber string) {
	fmt.Printf("%s  [%s] Return to Main Menu%s\n", Yellow, optionNumber, Reset)
}
