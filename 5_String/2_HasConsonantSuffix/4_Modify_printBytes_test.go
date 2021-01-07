// go test -v .\4_Modify_printBytes_test.go

package hangul

import "fmt"

func ExampleModifyPrintBytes() {
	s := []byte("가나다")
	s[2]++
	fmt.Println(string(s))
	//Output:
}
