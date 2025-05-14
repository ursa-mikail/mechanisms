package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const chunkSize = 4096

func overwriteFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("skipping non-regular file: %s", path)
	}

	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()

	size := info.Size()
	buf := make([]byte, chunkSize)
	for i := range buf {
		buf[i] = 0xFF
	}

	var written int64
	for written < size {
		toWrite := chunkSize
		if size-written < int64(chunkSize) {
			toWrite = int(size - written)
		}
		n, err := file.Write(buf[:toWrite])
		if err != nil {
			return err
		}
		written += int64(n)
	}

	fmt.Printf("Overwritten: %s\n", path)
	return nil
}

func overwriteFolder(folder string) error {
	return filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			return overwriteFile(path)
		}
		return nil
	})
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run overwrite.go <file-or-folder>")
		os.Exit(1)
	}

	path := os.Args[1]
	info, err := os.Stat(path)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	if info.Mode().IsRegular() {
		err = overwriteFile(path)
	} else if info.IsDir() {
		err = overwriteFolder(path)
	} else {
		fmt.Println("Unsupported file type.")
		os.Exit(1)
	}

	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

/*
go mod tidy 
go run overwrite_files_and_folders_N_times_with_FF_bytes_with_params.go /path/to/file_or_folder

or

go build -o overwrite_files_and_folders_N_times_with_FF_bytes_with_params
./overwrite_files_and_folders_N_times_with_FF_bytes_with_params /path/to/file_or_folder

📌 Notes
This overwrites only regular files, recursively if a folder is given.

Skips symlinks, special files, etc.

Uses 0xFF for overwriting (like b'\xff' in Python).

You can easily adapt it to add multiple passes (FF, 00, random) — let me know if you want that added.


*/