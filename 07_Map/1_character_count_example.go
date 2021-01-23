// go run ./1_character_count_example.go

package main

import (
	"fmt"
	"strings"
)

// countCharactersMap is a function that counts the occurrences of each character in a given string.
// It stores the character counts in a map and returns it.
func countCharactersMap(str string) map[string]int {
	counts := make(map[string]int)
	for _, char := range str {
		counts[string(char)]++
	}
	return counts
}

// countCharactersSlice is a function that counts the occurrences of each character in a given string.
// It stores the character counts in a slice and returns it.
func countCharactersSlice(str string) []string {
	counts := make([]string, 0)
	chars := strings.Split(str, "")
	for _, char := range chars {
		exists := false
		for i := 0; i < len(counts); i += 2 {
			if counts[i] == char {
				counts[i+1] = fmt.Sprint(1 + parseInt(counts[i+1]))
				exists = true
				break
			}
		}
		if !exists {
			counts = append(counts, char, "1")
		}
	}
	return counts
}

func parseInt(s string) int {
	var res int
	fmt.Sscanf(s, "%d", &res)
	return res
}

func main() {
	str := "Hello, world!"

	// Map Example
	charCountsMap := countCharactersMap(str)
	for char, count := range charCountsMap {
		fmt.Printf("Character '%s' count (Map): %d\n", char, count)
	}

	// Slice Example
	charCountsSlice := countCharactersSlice(str)
	for i := 0; i < len(charCountsSlice); i += 2 {
		char := charCountsSlice[i]
		count := charCountsSlice[i+1]
		fmt.Printf("Character '%s' count (Slice): %s\n", char, count)
	}
}
