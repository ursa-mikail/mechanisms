package main

import (
	"fmt"
	"runtime"
	"time"
)

func main() {
	var allocations [][]byte
	var maxSize int64
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var memStats runtime.MemStats
			runtime.ReadMemStats(&memStats)
			fmt.Printf("Allocated: %d MB, HeapSys: %d MB, NumGC: %d\n",
				memStats.Alloc/1024/1024, memStats.HeapSys/1024/1024, memStats.NumGC)
		}

		// Try to allocate 10MB blocks
		block := make([]byte, 10*1024*1024)
		allocations = append(allocations, block)
		maxSize += int64(len(block))
	}
}

/* 
Program continuously allocates memory in 10MB blocks while printing heap statistics every second. 
It stops when the system runs out of memory. The maxSize variable keeps track of the maximum allocation before failure.

NumGC: total number of completed garbage collection cycles since the program started

sample run:
Allocated: 0 MB, HeapSys: 3 MB, NumGC: 0
Allocated: 10 MB, HeapSys: 15 MB, NumGC: 1
Allocated: 20 MB, HeapSys: 27 MB, NumGC: 2
Allocated: 30 MB, HeapSys: 39 MB, NumGC: 2
Allocated: 40 MB, HeapSys: 51 MB, NumGC: 3
Allocated: 50 MB, HeapSys: 51 MB, NumGC: 3
Allocated: 60 MB, HeapSys: 63 MB, NumGC: 3
Allocated: 70 MB, HeapSys: 75 MB, NumGC: 3


*/