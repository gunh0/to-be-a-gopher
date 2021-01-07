// go test .\3_Example_printBytes_test.go

package hangul

import "fmt"

func Example_printBytes() {
	s := "가나다"
	for i := 0; i < len(s); i++ {
		fmt.Printf("%x:", s[i])
	}
	fmt.Println()
	//Output:
}
