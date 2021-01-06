package main

import "fmt"

func main() {
	for i, r := range "가나다" { // 3 bytes(24bits) per character is required.
		// Type : i-int(32bits), r-rune(32bits)
		fmt.Println(i, r)
	}
	fmt.Println(len("가나다")) // 9 bytes
}
