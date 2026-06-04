package utils

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"
)

func DefaultBuildTarget() string {
	if target := NormalizeBuildTarget(os.Getenv("GOOS"), ""); target != "" {
		return target
	}
	if target := NormalizeBuildTarget(runtime.GOOS, ""); target != "" {
		return target
	}
	return "linux"
}

func NormalizeBuildTarget(input, fallback string) string {
	switch strings.ToLower(strings.TrimSpace(input)) {
	case "win", "windows", "exe":
		return "windows"
	case "linux":
		return "linux"
	case "":
		return fallback
	default:
		return fallback
	}
}

func PromptBuildTarget(reader *bufio.Reader, fallback string) string {
	if reader == nil {
		reader = bufio.NewReader(os.Stdin)
	}
	fallback = NormalizeBuildTarget(fallback, "linux")
	fmt.Printf("%sBuild target (windows/linux, default: %s): %s", Green, fallback, Reset)
	input, _ := reader.ReadString('\n')
	target := NormalizeBuildTarget(input, fallback)
	if target == fallback && strings.TrimSpace(input) != "" && NormalizeBuildTarget(input, "") == "" {
		fmt.Printf("%s[!] Invalid build target, using %s%s\n", Yellow, fallback, Reset)
	}
	return target
}

func GoBuildEnv(goos string) []string {
	goos = NormalizeBuildTarget(goos, DefaultBuildTarget())
	env := os.Environ()
	env = setEnvValue(env, "GOOS", goos)
	if strings.TrimSpace(os.Getenv("GOARCH")) == "" {
		env = setEnvValue(env, "GOARCH", runtime.GOARCH)
	}
	return env
}

func setEnvValue(env []string, key, value string) []string {
	prefix := key + "="
	for i, item := range env {
		if strings.HasPrefix(item, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}
