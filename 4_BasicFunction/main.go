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

func facto2(n int) int {
	result := 1
	for n > 0 {
		result *= n
		n--
	}
	return result
}

func facto3(n int) int {
	result := 1
	for i := 2; i <= n; i++ {
		result *= i
	}
	return result
}

func main() {
	fmt.Println(facto(5))
	fmt.Println(facto2(5))
	fmt.Println(facto3(5))
}
