package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const (
	chunkSize    = 1024 * 1024 // 1 MB
	targetSizeMB = 100
)

type Permit struct {
	Algo      string   `json:"algo"`
	KeyHex    string   `json:"key_hex"`
	UsedBytes int      `json:"used_bytes"`
	MaxBytes  int64    `json:"max_bytes"`
	Domains   []string `json:"domains"`
	Revoked   bool     `json:"revoked"`
	Timestamp float64  `json:"timestamp"`
}

type Node struct {
	NodeID string `json:"node_id"`
	Prev   string `json:"prev"`
	Next   string `json:"next"`
	Permit Permit `json:"permit"`
}

type Metadata struct {
	TotalSize      int    `json:"total_size"`
	OriginalSHA256 string `json:"original_sha256"`
	ChunkCount     int    `json:"chunk_count"`
	ChunkSize      int    `json:"chunk_size"`
	FileSizeMB     int    `json:"file_size_mb"`
	Nodes          []Node `json:"nodes"`
}

type FileChunkManager struct {
	rootDir string
}

func NewFileChunkManager(rootDir string) *FileChunkManager {
	if rootDir == "" {
		rootDir = "."
	}
	return &FileChunkManager{rootDir: rootDir}
}

func (fcm *FileChunkManager) GenerateLargeFile(targetSizeMB int, outputPath string) (string, error) {
	if outputPath == "" {
		outputPath = filepath.Join(fcm.rootDir, "original_large_file.bin")
	}

	fmt.Printf("Generating %dMB file...\n", targetSizeMB)
	targetSize := targetSizeMB * 1024 * 1024

	file, err := os.Create(outputPath)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	written := 0
	buffer := make([]byte, chunkSize)

	for written < targetSize {
		remaining := targetSize - written
		currentChunkSize := chunkSize
		if remaining < chunkSize {
			currentChunkSize = remaining
		}

		// Read random bytes
		_, err := rand.Read(buffer[:currentChunkSize])
		if err != nil {
			return "", fmt.Errorf("failed to generate random data: %v", err)
		}

		n, err := file.Write(buffer[:currentChunkSize])
		if err != nil {
			return "", fmt.Errorf("failed to write to file: %v", err)
		}

		written += n
	}

	// Get file info to verify size
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to get file info: %v", err)
	}

	fmt.Printf("Generated file: %s (%d bytes, %.2f MB)\n",
		outputPath, info.Size(), float64(info.Size())/(1024*1024))

	return outputPath, nil
}

func (fcm *FileChunkManager) CalculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to calculate hash: %v", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (fcm *FileChunkManager) GenerateNodeID() (string, error) {
	bytes := make([]byte, 8)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (fcm *FileChunkManager) GenerateKeyHex() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (fcm *FileChunkManager) SplitFileDirectly(inputFilePath, outputDir string) (string, error) {
	if outputDir == "" {
		outputDir = filepath.Join(fcm.rootDir, "chunks")
	}

	fmt.Println("Splitting 100MB file directly into 100 chunks...")

	// Read the entire file
	data, err := os.ReadFile(inputFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read input file: %v", err)
	}

	fileSize := len(data)
	expectedSize := 100 * 1024 * 1024

	if fileSize != expectedSize {
		fmt.Printf("Warning: File size is %d bytes, expected %d bytes\n", fileSize, expectedSize)
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %v", err)
	}

	// Pre-generate all node IDs
	nodeIDs := make([]string, 100)
	for i := 0; i < 100; i++ {
		nodeID, err := fcm.GenerateNodeID()
		if err != nil {
			return "", fmt.Errorf("failed to generate node ID: %v", err)
		}
		nodeIDs[i] = nodeID
	}

	nodes := make([]Node, 100)
	totalChunks := 100

	for i := 0; i < totalChunks; i++ {
		startIdx := i * chunkSize
		endIdx := (i + 1) * chunkSize
		if endIdx > fileSize {
			endIdx = fileSize
		}

		chunkData := data[startIdx:endIdx]

		// Determine previous and next node IDs
		var prevNodeID, nextNodeID string
		if i > 0 {
			prevNodeID = nodeIDs[i-1]
		}
		if i < totalChunks-1 {
			nextNodeID = nodeIDs[i+1]
		}

		// Generate domains
		domains := []string{fmt.Sprintf("chunk_%02d.dat", i)}

		// Generate key
		keyHex, err := fcm.GenerateKeyHex()
		if err != nil {
			return "", fmt.Errorf("failed to generate key: %v", err)
		}

		// Create node
		node := Node{
			NodeID: nodeIDs[i],
			Prev:   prevNodeID,
			Next:   nextNodeID,
			Permit: Permit{
				Algo:      "AES-GCM",
				KeyHex:    keyHex,
				UsedBytes: len(chunkData),
				MaxBytes:  64 * 1024 * 1024 * 1024, // 64 GB
				Domains:   domains,
				Revoked:   false,
				Timestamp: 4313094.01 + float64(i),
			},
		}

		nodes[i] = node

		// Save chunk
		chunkPath := filepath.Join(outputDir, domains[0])
		if err := os.WriteFile(chunkPath, chunkData, 0644); err != nil {
			return "", fmt.Errorf("failed to write chunk file: %v", err)
		}

		fmt.Printf("Created chunk %d/%d: %s (%d bytes)\n", i+1, totalChunks, domains[0], len(chunkData))
	}

	// Calculate original file SHA256
	originalSHA256, err := fcm.CalculateSHA256(inputFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to calculate SHA256: %v", err)
	}

	// Create metadata
	metadata := Metadata{
		TotalSize:      fileSize,
		OriginalSHA256: originalSHA256,
		ChunkCount:     totalChunks,
		ChunkSize:      chunkSize,
		FileSizeMB:     100,
		Nodes:          nodes,
	}

	// Save metadata to JSON file
	metadataPath := filepath.Join(outputDir, "metadata.json")
	metadataJSON, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal metadata: %v", err)
	}

	if err := os.WriteFile(metadataPath, metadataJSON, 0644); err != nil {
		return "", fmt.Errorf("failed to write metadata file: %v", err)
	}

	fmt.Printf("Metadata saved to %s\n", metadataPath)

	// Also save a separate detailed nodes JSON file
	nodesMetadataPath := filepath.Join(fcm.rootDir, "chunks_metadata_detailed.json")
	if err := os.WriteFile(nodesMetadataPath, metadataJSON, 0644); err != nil {
		return "", fmt.Errorf("failed to write detailed metadata file: %v", err)
	}

	fmt.Printf("Detailed metadata saved to %s\n", nodesMetadataPath)
	return metadataPath, nil
}

func (fcm *FileChunkManager) ReassembleFromChunks(chunksDir, outputFilePath string) (string, error) {
	if chunksDir == "" {
		chunksDir = filepath.Join(fcm.rootDir, "chunks")
	}
	if outputFilePath == "" {
		outputFilePath = filepath.Join(fcm.rootDir, "reassembled_file.bin")
	}

	fmt.Println("Reassembling chunks...")

	// Load metadata
	metadataPath := filepath.Join(chunksDir, "metadata.json")
	metadataJSON, err := os.ReadFile(metadataPath)
	if err != nil {
		return "", fmt.Errorf("failed to read metadata file: %v", err)
	}

	var metadata Metadata
	if err := json.Unmarshal(metadataJSON, &metadata); err != nil {
		return "", fmt.Errorf("failed to unmarshal metadata: %v", err)
	}

	fmt.Printf("Found %d nodes in metadata\n", len(metadata.Nodes))

	// Create output file
	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to create output file: %v", err)
	}
	defer outputFile.Close()

	// Iterate through nodes in order
	for i, node := range metadata.Nodes {
		if len(node.Permit.Domains) == 0 {
			return "", fmt.Errorf("node %d has no domains", i)
		}

		chunkFilename := node.Permit.Domains[0]
		chunkPath := filepath.Join(chunksDir, chunkFilename)

		chunkData, err := os.ReadFile(chunkPath)
		if err != nil {
			return "", fmt.Errorf("failed to read chunk file %s: %v", chunkPath, err)
		}

		if _, err := outputFile.Write(chunkData); err != nil {
			return "", fmt.Errorf("failed to write chunk data: %v", err)
		}

		fmt.Printf("Added chunk %d/%d: %s (%d bytes)\n", i+1, len(metadata.Nodes), chunkFilename, len(chunkData))
	}

	// Verify size
	info, err := outputFile.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to get output file info: %v", err)
	}

	if info.Size() != int64(metadata.TotalSize) {
		return "", fmt.Errorf("size mismatch: expected %d, got %d", metadata.TotalSize, info.Size())
	}

	// Verify SHA256
	reassembledSHA256, err := fcm.CalculateSHA256(outputFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to calculate reassembled file SHA256: %v", err)
	}

	if reassembledSHA256 != metadata.OriginalSHA256 {
		return "", fmt.Errorf("SHA256 mismatch! Expected %s, got %s", metadata.OriginalSHA256, reassembledSHA256)
	}

	fmt.Printf("Successfully reassembled %s\n", outputFilePath)
	fmt.Printf("SHA256 verified: %s\n", reassembledSHA256)

	return outputFilePath, nil
}

func (fcm *FileChunkManager) VerifyFinalIntegrity(originalFile, finalFile string) (bool, error) {
	originalHash, err := fcm.CalculateSHA256(originalFile)
	if err != nil {
		return false, fmt.Errorf("failed to calculate original file hash: %v", err)
	}

	finalHash, err := fcm.CalculateSHA256(finalFile)
	if err != nil {
		return false, fmt.Errorf("failed to calculate final file hash: %v", err)
	}

	fmt.Printf("\n=== INTEGRITY VERIFICATION ===\n")
	fmt.Printf("Original file SHA256: %s\n", originalHash)
	fmt.Printf("Final file SHA256:    %s\n", finalHash)

	if originalHash == finalHash {
		fmt.Println("✅ SUCCESS: Files are identical! Data integrity verified.")
		return true, nil
	} else {
		fmt.Println("❌ FAILURE: Files are different! Data corruption detected.")
		return false, nil
	}
}

func (fcm *FileChunkManager) DisplayChunkInfo() error {
	chunksDir := filepath.Join(fcm.rootDir, "chunks")
	metadataPath := filepath.Join(chunksDir, "metadata.json")

	metadataJSON, err := os.ReadFile(metadataPath)
	if err != nil {
		return fmt.Errorf("failed to read metadata file: %v", err)
	}

	var metadata Metadata
	if err := json.Unmarshal(metadataJSON, &metadata); err != nil {
		return fmt.Errorf("failed to unmarshal metadata: %v", err)
	}

	fmt.Printf("\n=== CHUNK INFORMATION ===\n")
	fmt.Printf("Total chunks: %d\n", metadata.ChunkCount)
	fmt.Printf("Chunk size: %d bytes\n", metadata.ChunkSize)
	fmt.Printf("Total file size: %d bytes\n", metadata.TotalSize)
	fmt.Printf("Expected chunks: 100\n")

	// Count actual chunk files
	files, err := os.ReadDir(chunksDir)
	if err != nil {
		return fmt.Errorf("failed to read chunks directory: %v", err)
	}

	chunkCount := 0
	for _, file := range files {
		if !file.IsDir() {
			name := file.Name()
			if len(name) >= 11 && name[:6] == "chunk_" && name[len(name)-4:] == ".dat" {
				chunkCount++
			}
		}
	}
	fmt.Printf("Actual chunk files: %d\n", chunkCount)

	// Display first few nodes as example
	fmt.Printf("\nFirst 3 nodes example:\n")
	for i := 0; i < 3 && i < len(metadata.Nodes); i++ {
		node := metadata.Nodes[i]
		fmt.Printf("Node %d: %s -> %s\n", i, node.NodeID, node.Permit.Domains[0])
	}

	// Display last few nodes as example
	fmt.Printf("\nLast 3 nodes example:\n")
	start := len(metadata.Nodes) - 3
	if start < 0 {
		start = 0
	}
	for i := start; i < len(metadata.Nodes); i++ {
		node := metadata.Nodes[i]
		fmt.Printf("Node %d: %s -> %s\n", i, node.NodeID, node.Permit.Domains[0])
	}

	return nil
}

func main() {
	rootDir := "."
	fcm := NewFileChunkManager(rootDir)

	absPath, err := filepath.Abs(rootDir)
	if err != nil {
		log.Fatalf("Failed to get absolute path: %v", err)
	}
	fmt.Printf("Working in directory: %s\n", absPath)

	startTime := time.Now()

	// Step 1: Generate exactly 100MB file
	fmt.Println("\n=== STEP 1: Generating 100MB file ===")
	originalFile, err := fcm.GenerateLargeFile(100, "")
	if err != nil {
		log.Fatalf("Failed to generate large file: %v", err)
	}

	originalSHA256, err := fcm.CalculateSHA256(originalFile)
	if err != nil {
		log.Fatalf("Failed to calculate SHA256: %v", err)
	}
	fmt.Printf("Original file SHA256: %s\n", originalSHA256)

	// Step 2: Split directly into 100 chunks of 1MB each
	fmt.Println("\n=== STEP 2: Splitting into 100 chunks ===")
	chunksDir := filepath.Join(rootDir, "chunks")
	_, err = fcm.SplitFileDirectly(originalFile, chunksDir)
	if err != nil {
		log.Fatalf("Failed to split file: %v", err)
	}

	// Step 3: Reassemble from chunks
	fmt.Println("\n=== STEP 3: Reassembling from chunks ===")
	reassembledFile, err := fcm.ReassembleFromChunks("", "")
	if err != nil {
		log.Fatalf("Failed to reassemble from chunks: %v", err)
	}

	// Step 4: Final integrity check
	fmt.Println("\n=== STEP 4: Verifying integrity ===")
	success, err := fcm.VerifyFinalIntegrity(originalFile, reassembledFile)
	if err != nil {
		log.Fatalf("Failed to verify integrity: %v", err)
	}

	// Display chunk information
	if err := fcm.DisplayChunkInfo(); err != nil {
		log.Fatalf("Failed to display chunk info: %v", err)
	}

	// List all generated files
	fmt.Printf("\n=== GENERATED FILES ===\n")
	files, err := os.ReadDir(rootDir)
	if err != nil {
		log.Fatalf("Failed to read directory: %v", err)
	}

	for _, file := range files {
		filePath := filepath.Join(rootDir, file.Name())
		info, err := file.Info()
		if err != nil {
			continue
		}

		if file.IsDir() {
			dirSize, fileCount := fcm.getDirectorySize(filePath)
			fmt.Printf("📁 %s/ (%d files, %d bytes)\n", file.Name(), fileCount, dirSize)
		} else {
			fmt.Printf("📄 %s (%d bytes)\n", file.Name(), info.Size())
		}
	}

	// Verify we have exactly 100 chunks
	chunkFiles, err := fcm.countChunkFiles(chunksDir)
	if err != nil {
		log.Fatalf("Failed to count chunk files: %v", err)
	}

	fmt.Printf("\n✅ VERIFICATION: Found %d chunk files (expected: 100)\n", chunkFiles)
	if chunkFiles == 100 {
		fmt.Println("🎉 SUCCESS: Exactly 100 chunks created!")
	} else {
		fmt.Printf("⚠️  WARNING: Expected 100 chunks, but found %d\n", chunkFiles)
	}

	if success {
		fmt.Printf("\n✨ All operations completed successfully in %v\n", time.Since(startTime))
	}
}

func (fcm *FileChunkManager) getDirectorySize(dirPath string) (int64, int) {
	var totalSize int64
	var fileCount int

	filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			totalSize += info.Size()
			fileCount++
		}
		return nil
	})

	return totalSize, fileCount
}

func (fcm *FileChunkManager) countChunkFiles(chunksDir string) (int, error) {
	files, err := os.ReadDir(chunksDir)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, file := range files {
		if !file.IsDir() {
			name := file.Name()
			// Check if filename matches pattern chunk_XX.dat
			if len(name) == 11 && name[:6] == "chunk_" && name[8:] == ".dat" {
				if _, err := strconv.Atoi(name[6:8]); err == nil {
					count++
				}
			}
		}
	}
	return count, nil
}

/*

% go run main.go
Working in directory: /Users/chanfamily/Progamming/go/trial_data_chunking

=== STEP 1: Generating 100MB file ===
Generating 100MB file...
Generated file: original_large_file.bin (104857600 bytes, 100.00 MB)
Original file SHA256: 0d0702f2eb82f3289d1cd72d4abcc5e24c772091d3332c6ef46554024dc43770

=== STEP 2: Splitting into 100 chunks ===
Splitting 100MB file directly into 100 chunks...
Created chunk 1/100: chunk_00.dat (1048576 bytes)
Created chunk 2/100: chunk_01.dat (1048576 bytes)
:
Created chunk 100/100: chunk_99.dat (1048576 bytes)
Metadata saved to chunks/metadata.json
Detailed metadata saved to chunks_metadata_detailed.json

=== STEP 3: Reassembling from chunks ===
Reassembling chunks...
Found 100 nodes in metadata
Added chunk 1/100: chunk_00.dat (1048576 bytes)
Added chunk 2/100: chunk_01.dat (1048576 bytes)
:
Added chunk 100/100: chunk_99.dat (1048576 bytes)
Successfully reassembled reassembled_file.bin
SHA256 verified: 0d0702f2eb82f3289d1cd72d4abcc5e24c772091d3332c6ef46554024dc43770

=== STEP 4: Verifying integrity ===

=== INTEGRITY VERIFICATION ===
Original file SHA256: 0d0702f2eb82f3289d1cd72d4abcc5e24c772091d3332c6ef46554024dc43770
Final file SHA256:    0d0702f2eb82f3289d1cd72d4abcc5e24c772091d3332c6ef46554024dc43770
✅ SUCCESS: Files are identical! Data integrity verified.

=== CHUNK INFORMATION ===
Total chunks: 100
Chunk size: 1048576 bytes
Total file size: 104857600 bytes
Expected chunks: 100
Actual chunk files: 100

First 3 nodes example:
Node 0: 3a7eda4b7d9e3e1e -> chunk_00.dat
Node 1: 1d2a1d4bb81a2137 -> chunk_01.dat
Node 2: 45ec2b9ee03b8300 -> chunk_02.dat

Last 3 nodes example:
Node 97: 42d1e1c459bcdafc -> chunk_97.dat
Node 98: 1caeaed4a683fc3e -> chunk_98.dat
Node 99: e1c7dbfd17cc7954 -> chunk_99.dat

=== GENERATED FILES ===
📄 .DS_Store (6148 bytes)
📁 .git/ (72 files, 38434 bytes)
📄 .gitignore (44 bytes)
📁 .vscode/ (1 files, 255 bytes)
📁 chunks/ (101 files, 104901573 bytes)
📄 chunks_metadata_detailed.json (43973 bytes)
📄 go.mod (38 bytes)
📁 lib/ (1 files, 293 bytes)
📄 main.go (15034 bytes)
📄 original_large_file.bin (104857600 bytes)
📄 readme.md (335 bytes)
📄 reassembled_file.bin (104857600 bytes)
📄 trial_00.code-workspace (692 bytes)
📁 util/ (1 files, 63 bytes)

✅ VERIFICATION: Found 0 chunk files (expected: 100)
⚠️  WARNING: Expected 100 chunks, but found 0

✨ All operations completed successfully in 488.245541ms


% go mod init trial_data_chunking
% go mod tidy
% go run main.go

*/
