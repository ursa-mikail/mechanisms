package main

import (
	"fmt"
	//"math/rand"
	"os"
	"path/filepath"

	"crypto/rand"
	"log"
)

const chunkSize = 4096

func overwriteFile(path string) error {
	// Define the desired length of the byte slice
	length := 1

	// Create a byte slice with the specified length
	randomBytes := make([]byte, length)

	// Read random bytes from crypto/rand into the slice
	_, err := rand.Read(randomBytes)
	if err != nil {
		log.Fatalf("Error generating random bytes: %s", err)
	}

	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()

	size := info.Size()
	buf := make([]byte, chunkSize)
	for i := range buf {
		buf[i] = randomBytes[0] // 0xFF		
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
	return nil
}

func overwriteAndDeleteFile(path string, N int) error {
	for i := 0; i < N; i++ {
		fmt.Printf("Pass %d: Overwriting file %s\n", i+1, path)
		err := overwriteFile(path)
		if err != nil {
			return err
		}
	}
	fmt.Printf("Deleting file: %s\n", path)
	return os.Remove(path)
}

func overwriteFolder(folder string, N int) error {
	err := filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		for i := 0; i < N; i++ {
			fmt.Printf("Pass %d: Overwriting file %s\n", i+1, path)
			if err := overwriteFile(path); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

func deleteFolder(folder string) error {
	fmt.Printf("Deleting folder: %s\n", folder)
	return os.RemoveAll(folder)
}

func createTestFile(path string, size int) error {
	data := make([]byte, size)
	rand.Read(data)
	return os.WriteFile(path, data, 0600)
}

func createTestFolderStructure(base string) error {
	subfolder := filepath.Join(base, "subfolder")
	os.MkdirAll(subfolder, 0700)

	files := []string{
		filepath.Join(base, "file1.txt"),
		filepath.Join(base, "file2.txt"),
		filepath.Join(subfolder, "nested1.txt"),
		filepath.Join(subfolder, "nested2.txt"),
	}

	for _, f := range files {
		if err := createTestFile(f, 2048); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	N := 3 // Number of overwrite passes

	// === Test Single File ===
	testFile := "test_single.txt"
	fmt.Println("Creating test file:", testFile)
	_ = createTestFile(testFile, 4096)

	if err := overwriteAndDeleteFile(testFile, N); err != nil {
		fmt.Println("Error in single file test:", err)
	}

	// === Test Folder with Files ===
	testFolder := "test_folder"
	fmt.Println("Creating test folder:", testFolder)
	_ = createTestFolderStructure(testFolder)

	if err := overwriteFolder(testFolder, N); err != nil {
		fmt.Println("Error overwriting folder:", err)
	}
	if err := deleteFolder(testFolder); err != nil {
		fmt.Println("Error deleting folder:", err)
	}
}

/*
go mod tidy 
go run overwrite_files_and_folders_N_times_with_random_bytes.go

Creating test file: test_single.txt
Pass 1: Overwriting file test_single.txt
Pass 2: Overwriting file test_single.txt
Pass 3: Overwriting file test_single.txt
Deleting file: test_single.txt
Creating test folder: test_folder
Pass 1: Overwriting file test_folder/file1.txt
Pass 2: Overwriting file test_folder/file1.txt
Pass 3: Overwriting file test_folder/file1.txt
Pass 1: Overwriting file test_folder/file2.txt
Pass 2: Overwriting file test_folder/file2.txt
Pass 3: Overwriting file test_folder/file2.txt
Pass 1: Overwriting file test_folder/subfolder/nested1.txt
Pass 2: Overwriting file test_folder/subfolder/nested1.txt
Pass 3: Overwriting file test_folder/subfolder/nested1.txt
Pass 1: Overwriting file test_folder/subfolder/nested2.txt
Pass 2: Overwriting file test_folder/subfolder/nested2.txt
Pass 3: Overwriting file test_folder/subfolder/nested2.txt
Deleting folder: test_folder
*/