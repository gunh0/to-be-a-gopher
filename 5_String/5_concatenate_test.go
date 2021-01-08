// go test -v .\5_concatenate.go
package main

import (
	"fmt"
)

func Example_strCat() {
	s := "abc"
	ps := &s
	s += "def"
	fmt.Println(s)
	fmt.Println(*ps)
	// Output:
}
