package pcutilities

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

func effectiveTermWidth() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w < 40 {
		if s := os.Getenv("COLUMNS"); s != "" {
			var n int
			_, _ = fmt.Sscanf(s, "%d", &n)
			if n >= 40 {
				w = n
			}
		}
	}
	if w < 72 {
		w = 72
	}
	if w > 220 {
		w = 220
	}
	return w
}
