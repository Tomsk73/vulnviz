package cvss

import (
	"strings"
	"unicode/utf8"
)

// Clip returns s cut to at most n runes (adding an ellipsis when cut), with
// invalid UTF-8 and NUL bytes removed so the result is safe to store.
func Clip(s string, n int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	s = strings.ReplaceAll(s, "\x00", "")
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos] + "…"
		}
		i++
	}
	return s
}
