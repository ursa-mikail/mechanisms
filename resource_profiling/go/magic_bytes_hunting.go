package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unsafe"
)

var magicBytes = []byte{0x60, 0x0d, 0xf0, 0x0d, 0xc0, 0x1a}

func main() {
	// Store the magic bytes in a variable
	mem := make([]byte, len(magicBytes))
	copy(mem, magicBytes)
	// Print the memory address for debugging
	fmt.Printf("Target magic bytes stored at: %p\n", unsafe.Pointer(&mem[0]))

	pid := os.Getpid()
	fmt.Printf("Scanner process running. Looking for magic bytes in PID %d...\n", pid)

	// Read memory of all mapped regions
	scanMemory(pid)
}

func scanMemory(pid int) {
	// Open memory for reading
	memFile, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		fmt.Println("Error opening memory:", err)
		return
	}
	defer memFile.Close()

	// Read the memory map
	mapsFile, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		fmt.Println("Error opening memory map:", err)
		return
	}
	defer mapsFile.Close()

	// Scan each memory region
	scanner := bufio.NewScanner(mapsFile)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " ")
		if len(parts) < 1 {
			continue
		}

		addrRange := strings.Split(parts[0], "-")
		if len(addrRange) != 2 {
			continue
		}

		// Parse start and end addresses
		start, err := strconv.ParseUint(addrRange[0], 16, 64)
		if err != nil {
			continue
		}

		end, err := strconv.ParseUint(addrRange[1], 16, 64)
		if err != nil {
			continue
		}

		// Skip if not readable or too large
		if !strings.Contains(parts[1], "r") || end-start > 10*1024*1024 {
			continue
		}

		// Read memory segment
		size := end - start
		buf := make([]byte, size)

		_, err = memFile.Seek(int64(start), 0)
		if err != nil {
			continue
		}

		_, err = io.ReadFull(memFile, buf)
		if err != nil {
			continue
		}

		// Search for magic bytes
		offset := bytes.Index(buf, magicBytes)
		if offset != -1 {
			fmt.Printf("Found magic bytes at: 0x%x\n", start+uint64(offset))
		}
	}
}

/*
Target magic bytes stored at: 0xc0000a0040
Scanner process running. Looking for magic bytes in PID 12...
Found magic bytes at: 0x55f1b0
Found magic bytes at: 0xc0000a0040

This program requires Added/assumed permissible permission checking to only read readable memory regions.

Note: 
1. file seeking and reading works better instead of PtracePeekText (which would require attaching to the process first and doesn't work with large memory regions)
2. size limits to avoid trying to read extremely large memory chunks
*/