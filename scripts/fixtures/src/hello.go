// Go fixture: statically linked runtime, own pclntab, goroutines.
package main

import (
	"fmt"
	"sync"
)

func sum(xs []int, wg *sync.WaitGroup, out *int) {
	defer wg.Done()
	for _, x := range xs {
		*out += x
	}
}

func main() {
	var wg sync.WaitGroup
	a, b := 0, 0
	wg.Add(2)
	go sum([]int{1, 2, 3, 4}, &wg, &a)
	go sum([]int{5, 6, 7, 8}, &wg, &b)
	wg.Wait()
	fmt.Println("Hello from Go:", a, b)
}
