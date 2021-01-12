// 2_HasConsonantSuffix> go test 2_hangul_test.go hangul.go
// --- FAIL: ExampleHasConsonantSuffix (0.00s)
// got:
// false
// true
// false
// want:
// .
// FAIL
// FAIL    command-line-arguments  0.189s
// FAIL

// if Modify Output:
// 2_HasConsonantSuffix> go test hangul_test.go hangul.go
// ok      command-line-arguments  0.115s

package hangul

import "fmt"

func ExampleHasConsonantSuffix() {
	fmt.Println(HasConsonantSuffix("Go 언어"))
	fmt.Println(HasConsonantSuffix("그럼"))
	fmt.Println(HasConsonantSuffix("반 갑 습 니 다!"))
	// Output:
	// .
}
