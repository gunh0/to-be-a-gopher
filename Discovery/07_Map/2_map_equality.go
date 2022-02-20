// go run 2_map_equality.go
package main

import (
	"fmt"
	"reflect"
)

func main() {
	map1 := map[string]int{"a": 1, "b": 2, "c": 3}
	map2 := map[string]int{"a": 1, "b": 2, "c": 3}
	map3 := map[string]int{"a": 1, "b": 2, "c": 4}

	fmt.Println("Map 1 and Map 2 are equal:", reflect.DeepEqual(map1, map2))
	fmt.Println("Map 1 and Map 3 are equal:", reflect.DeepEqual(map1, map3))
}
