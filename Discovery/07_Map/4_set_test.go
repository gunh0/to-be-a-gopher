// go test ./4_set_test.go
package main

import "fmt"

// hasDupeRune checks if a string has any duplicate runes.
// It returns true if there are duplicates, false otherwise.
func hasDupeRune(s string) bool {
	runeSet := map[rune]struct{}{}
	for _, r := range s {
		if _, exists := runeSet[r]; exists {
			return true
		}
		runeSet[r] = struct{}{}
	}
	return false
}

func ExampleHasDupeRune() {
	fmt.Println(hasDupeRune("aaa aaa"))        // true
	fmt.Println(hasDupeRune("abc"))            // false
	fmt.Println(hasDupeRune("Hello, world!"))  // true
	fmt.Println(hasDupeRune("Testing 123...")) // true
}
