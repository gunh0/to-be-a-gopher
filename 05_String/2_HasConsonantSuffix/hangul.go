// Package hangul provides basic functions for Hangul processing.package 5_String
package hangul

var (
	start = rune(44032) // "가"
	end   = rune(55204) // "힣"
)

// HasConsonantSuffix returns true if s has hangle consonant jamo at the end.
func HasConsonantSuffix(s string) bool {
	numEnds := 28
	result := false
	for _, r := range s {
		if start <= r && r < end {
			index := int(r - start)
			result = index%numEnds != 0
		}
	}
	return result
}
