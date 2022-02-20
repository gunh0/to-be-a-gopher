// go test ./3_maps_test.go
package main

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

func count(s string, codeCount map[rune]int) {
	for _, r := range s {
		codeCount[r]++
	}
}

func TestCount_deepEqual(t *testing.T) {
	codeCount := map[rune]int{}
	count("가나다나", codeCount)
	expectedCount := map[rune]int{'가': 1, '나': 2, '다': 1}
	if !reflect.DeepEqual(expectedCount, codeCount) {
		t.Error("codeCount mismatch:", codeCount)
	}
}

func TestCount_if(t *testing.T) {
	codeCount := map[rune]int{}
	count("가나다나", codeCount)
	if len(codeCount) != 3 {
		t.Error("codeCount:", codeCount)
		t.Fatal("count should be 3 but:", len(codeCount))
	}
	if codeCount['가'] != 1 || codeCount['나'] != 2 || codeCount['다'] != 1 {
		t.Error("codeCount mismatch:", codeCount)
	}
}

func ExampleCount_sort() {
	codeCount := map[rune]int{}
	count("가나다나", codeCount)
	var keys []int
	for key := range codeCount {
		keys = append(keys, int(key))
	}
	sort.Ints(keys)
	for _, key := range keys {
		fmt.Println(string(rune(key)), codeCount[rune(key)])
	}
	// Output:
	// 가 1
	// 나 2
	// 다 1
}
