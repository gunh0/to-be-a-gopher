// go test .\3_Appending_to_a_slice.go
package main

import "fmt"

func Example_append() {
	f1 := []string{"AAA", "BBB", "CCC"}
	f2 := []string{"DDD", "EEE"}
	f3 := append(f1, f2...)
	f4 := append(f1[:2], f2...)

	fmt.Println(f1)
	fmt.Println(f2)
	fmt.Println(f3)
	fmt.Println(f4)
	// Output:
}
