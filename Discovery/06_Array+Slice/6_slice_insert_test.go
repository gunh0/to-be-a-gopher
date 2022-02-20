// go test ./6_slice_insert_test.go 
package main

import "fmt"

func insert(array []string, index int, element string) []string {
	result := append(array, element)
	copy(result[index+1:], result[index:])
	result[index] = element
	return result
}

func Example_InsertTest() {
	array := []string{"1", "2", "3"}
	array = insert(array, 1, "5")
	fmt.Println(array)
	// Output:
}