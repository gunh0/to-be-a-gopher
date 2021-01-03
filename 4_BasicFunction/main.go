// Package main implements factorial.
package main

import "fmt"

// facto returns n!.
func facto(n int) int {
	if n <= 0 {
		return 1
	}
	return n * facto(n-1)
}

func main() {
	fmt.Println(facto(5))
}
