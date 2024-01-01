package main

import (
	"fmt"
	"io"
	"strings"
)

// Empty is a generic type struct that can operate on any type T.
type Empty[T any] struct{}

// Nop is a method on the Empty struct that returns the same value it receives.
// It demonstrates a simple operation using Go generics.
func (Empty[T]) Nop(x T) T {
	return x
}

func main() {
	// Create an instance of Empty for string types.
	e := Empty[string]{}
	// Use the Nop method to return the string "Hello, World!" and print it.
	fmt.Println(e.Nop("Hello, World!"))

	// Create an instance of Empty for int types.
	ei := Empty[int]{}
	// Use the Nop method to return the integer 42 and print it.
	fmt.Println(ei.Nop(42))

	// Create an instance of Empty for the io.Reader interface.
	er := Empty[io.Reader]{}
	// Use the Nop method with a string reader and store the returned reader.
	reader := er.Nop(strings.NewReader("Hello, Go!"))
	// Read all data from the reader and store it in the variable 'data'.
	data, _ := io.ReadAll(reader)
	// Print the data as a string.
	fmt.Printf("%s\n", data)
}
