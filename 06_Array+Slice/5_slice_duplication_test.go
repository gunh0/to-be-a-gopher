// go test ./5_slice_duplication_test.go
package main

import "fmt"

func Example_sliceCopy() {
	src := []int{30, 20, 50, 10, 40}
	dest := make([]int, len(src))
	for i := range src {
		dest[i] = src[i]
	}
	fmt.Println(dest)
	// Output:
}

func Example_sliceCopyFunc() {
	src := []int{30, 20, 50, 10, 40}
	dest := make([]int, len(src))
	copy(dest, src)
	fmt.Println(dest)
	// Output:
}

func Example_sliceCopyAppend() {
	src := []int{30, 20, 50, 10, 40}
	dest := append([]int(nil), src...)
	copy(dest, src)
	fmt.Println(dest)
	// Output:
}
