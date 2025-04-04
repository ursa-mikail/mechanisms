package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"time"
)

func main() {
	debug.SetMemoryLimit(500 * 1024 * 1024) // Optional: Set memory limit to 500MB

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

			// Simulate a memory overrun by detecting an imminent crash
			if memStats.Alloc > 450*1024*1024 { // Dump before reaching 500MB limit
				dumpHeap("heap_overrun_dump.prof")
				fmt.Println("Heap dump saved. Exiting...")
				fmt.Println("display_heap_overrun_dump ...")
				display_heap_overrun_dump()
				os.Exit(1)
			}
		}

		// Allocate memory in 10MB blocks
		block := make([]byte, 10*1024*1024)
		allocations = append(allocations, block)
		maxSize += int64(len(block))
	}
}

// dumpHeap saves the heap profile to a file
func dumpHeap(filename string) {
	f, err := os.Create(filename)
	if err != nil {
		fmt.Println("Failed to create heap dump:", err)
		return
	}
	defer f.Close()

	if err := pprof.WriteHeapProfile(f); err != nil {
		fmt.Println("Failed to write heap profile:", err)
	}
}

func display_heap_overrun_dump() {
	// Open the heap profile dump file
	file, err := os.Open("heap_overrun_dump.prof")
	if err != nil {
		fmt.Println("Error opening heap dump file:", err)
		return
	}
	defer file.Close()

	// Read and print the heap profile
	fmt.Println("Heap Profile Dump:\n")
	err = pprof.Lookup("heap").WriteTo(os.Stdout, 1)
	if err != nil {
		fmt.Println("Error writing heap profile:", err)
	}
}

/*

Allocated: 0 MB, HeapSys: 3 MB, NumGC: 0
Allocated: 10 MB, HeapSys: 15 MB, NumGC: 1
Allocated: 20 MB, HeapSys: 27 MB, NumGC: 2
Allocated: 30 MB, HeapSys: 39 MB, NumGC: 2
Allocated: 40 MB, HeapSys: 51 MB, NumGC: 3
Allocated: 50 MB, HeapSys: 51 MB, NumGC: 3
Allocated: 60 MB, HeapSys: 63 MB, NumGC: 3
Allocated: 70 MB, HeapSys: 75 MB, NumGC: 3
Allocated: 80 MB, HeapSys: 87 MB, NumGC: 4
Allocated: 90 MB, HeapSys: 99 MB, NumGC: 4
Allocated: 100 MB, HeapSys: 111 MB, NumGC: 4
Allocated: 110 MB, HeapSys: 111 MB, NumGC: 4
Allocated: 120 MB, HeapSys: 123 MB, NumGC: 4
Allocated: 130 MB, HeapSys: 135 MB, NumGC: 4
Allocated: 140 MB, HeapSys: 147 MB, NumGC: 4
Allocated: 150 MB, HeapSys: 159 MB, NumGC: 4
Allocated: 160 MB, HeapSys: 171 MB, NumGC: 5
Allocated: 170 MB, HeapSys: 171 MB, NumGC: 5
Allocated: 180 MB, HeapSys: 183 MB, NumGC: 5
Allocated: 190 MB, HeapSys: 195 MB, NumGC: 5
Allocated: 200 MB, HeapSys: 207 MB, NumGC: 5
Allocated: 210 MB, HeapSys: 219 MB, NumGC: 5
Allocated: 220 MB, HeapSys: 231 MB, NumGC: 5
Allocated: 230 MB, HeapSys: 231 MB, NumGC: 5
Allocated: 240 MB, HeapSys: 243 MB, NumGC: 5
Allocated: 250 MB, HeapSys: 255 MB, NumGC: 5
Allocated: 260 MB, HeapSys: 267 MB, NumGC: 5
Allocated: 270 MB, HeapSys: 279 MB, NumGC: 5
Allocated: 280 MB, HeapSys: 291 MB, NumGC: 5
Allocated: 290 MB, HeapSys: 291 MB, NumGC: 5
Allocated: 300 MB, HeapSys: 303 MB, NumGC: 5
Allocated: 310 MB, HeapSys: 315 MB, NumGC: 5
Allocated: 320 MB, HeapSys: 327 MB, NumGC: 6
Allocated: 330 MB, HeapSys: 339 MB, NumGC: 6
Allocated: 340 MB, HeapSys: 351 MB, NumGC: 6
Allocated: 350 MB, HeapSys: 351 MB, NumGC: 6
Allocated: 360 MB, HeapSys: 363 MB, NumGC: 6
Allocated: 370 MB, HeapSys: 375 MB, NumGC: 6
Allocated: 380 MB, HeapSys: 387 MB, NumGC: 6
Allocated: 390 MB, HeapSys: 399 MB, NumGC: 6
Allocated: 400 MB, HeapSys: 411 MB, NumGC: 6
Allocated: 410 MB, HeapSys: 411 MB, NumGC: 6
Allocated: 420 MB, HeapSys: 423 MB, NumGC: 6
Allocated: 430 MB, HeapSys: 435 MB, NumGC: 6
Allocated: 440 MB, HeapSys: 447 MB, NumGC: 6
Allocated: 450 MB, HeapSys: 459 MB, NumGC: 6
Heap dump saved. Exiting...

// alternatively instead of display_heap_overrun_dump()
1. Use go tool pprof to Inspect the Dump
go tool pprof -top heap_overrun_dump.prof

2. Print a Human-Readable Report
go tool pprof -text heap_overrun_dump.prof

3. Generate a Graphical Report
go tool pprof -web heap_overrun_dump.prof

4. Print the Raw Contents
cat heap_overrun_dump.prof


display_heap_overrun_dump ...
Heap Profile Dump:

heap profile: 17: 167772368 [18: 167772376] @ heap/1048576
0: 0 [1: 8] @ 0x47d59d 0x47d466 0x47d1dc 0x49fe7e 0x4a0265 0x4cf90c 0x4cf84e 0x43ca9d 0x4726a1
#	0x47d59c	sync.(*Pool).pinSlow+0xfc	/usr/local/go-faketime/src/sync/pool.go:237
#	0x47d465	sync.(*Pool).pin+0x45		/usr/local/go-faketime/src/sync/pool.go:220
#	0x47d1db	sync.(*Pool).Get+0x1b		/usr/local/go-faketime/src/sync/pool.go:135
#	0x49fe7d	fmt.newPrinter+0x1d		/usr/local/go-faketime/src/fmt/print.go:152
#	0x4a0264	fmt.Fprintf+0x44		/usr/local/go-faketime/src/fmt/print.go:223
#	0x4cf90b	fmt.Printf+0x18b		/usr/local/go-faketime/src/fmt/print.go:233
#	0x4cf84d	main.main+0xcd			/tmp/sandbox4164686184/prog.go:26
#	0x43ca9c	runtime.main+0x27c		/usr/local/go-faketime/src/runtime/proc.go:283

1: 208 [1: 208] @ 0x49d33a 0x47d271 0x49fe7e 0x4a0265 0x4cf90c 0x4cf84e 0x43ca9d 0x4726a1
#	0x49d339	fmt.init.func1+0x19	/usr/local/go-faketime/src/fmt/print.go:147
#	0x47d270	sync.(*Pool).Get+0xb0	/usr/local/go-faketime/src/sync/pool.go:155
#	0x49fe7d	fmt.newPrinter+0x1d	/usr/local/go-faketime/src/fmt/print.go:152
#	0x4a0264	fmt.Fprintf+0x44	/usr/local/go-faketime/src/fmt/print.go:223
#	0x4cf90b	fmt.Printf+0x18b	/usr/local/go-faketime/src/fmt/print.go:233
#	0x4cf84d	main.main+0xcd		/tmp/sandbox4164686184/prog.go:26
#	0x43ca9c	runtime.main+0x27c	/usr/local/go-faketime/src/runtime/proc.go:283

16: 167772160 [16: 167772160] @ 0x4cf9d1 0x43ca9d 0x4726a1
#	0x4cf9d0	main.main+0x250		/tmp/sandbox4164686184/prog.go:40
#	0x43ca9c	runtime.main+0x27c	/usr/local/go-faketime/src/runtime/proc.go:283


# runtime.MemStats
# Alloc = 473221184
# TotalAlloc = 473230888
# Sys = 487369080
# Lookups = 0
# Mallocs = 449
# Frees = 106
# HeapAlloc = 473221184
# HeapSys = 482017280
# HeapIdle = 8413184
# HeapInuse = 473604096
# HeapReleased = 8306688
# HeapObjects = 343
# Stack = 327680 / 327680
# MSpan = 33120 / 48960
# MCache = 9664 / 15704
# BuckHashSys = 1443087
# GCSys = 2468144
# OtherSys = 1048225
# NextGC = 502996692
# LastGC = 1257894032000000000
# PauseNs = [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
# PauseEnd = [1257894001000000000 1257894002000000000 1257894004000000000 1257894008000000000 1257894016000000000 1257894032000000000 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
# NumGC = 6
# NumForcedGC = 0
# GCCPUFraction = 0
# DebugGC = false
# MaxRSS = 66846720
*/