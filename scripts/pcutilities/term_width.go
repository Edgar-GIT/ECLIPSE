package pcutilities

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

func effectiveTermWidth() int {
	w := 0
	for _, fd := range []uintptr{os.Stdout.Fd(), os.Stderr.Fd(), os.Stdin.Fd()} {
		if ww, _, err := term.GetSize(int(fd)); err == nil && ww >= 30 {
			w = ww
			break
		}
	}
	if w < 30 {
		if s := os.Getenv("COLUMNS"); s != "" {
			var n int
			_, _ = fmt.Sscanf(s, "%d", &n)
			if n >= 30 {
				w = n
			}
		}
	}
	if w < 48 {
		w = 48
	}
	if w > 220 {
		w = 220
	}
	return w
}
