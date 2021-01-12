// go test .\1_Example_array_test.go
package main

import "fmt"

func Example_array() {
	fruits := [4]string{"Apple", "Banana", "Tomato", "Avocado"}
	for _, fruit := range fruits {
		fmt.Printf("%s is delicious.\n", fruit)
	}
	// Output:
}
