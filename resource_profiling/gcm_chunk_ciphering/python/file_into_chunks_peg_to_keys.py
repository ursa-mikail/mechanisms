"""
JSON Metadata Structure:
The metadata.json and chunks_metadata_detailed.json will contain:
100 nodes with unique node_id values
Each node points to chunk_00.dat through chunk_99.dat
Linked list structure with proper prev and next pointers
Complete permit information for each chunk

There are 100 chunks (00-99) with 100 corresponding node IDs in the JSON metadata.
"""
import os
import json
import zipfile
import hashlib
import secrets
from pathlib import Path

class FileChunkManager:
    def __init__(self, root_dir='.'):
        self.root_dir = root_dir
        self.chunk_size = 1024 * 1024  # 1 MB
        
    def generate_large_file(self, target_size_mb=100, output_path=None):
        """Generate a large file with random data"""
        if output_path is None:
            output_path = os.path.join(self.root_dir, "original_large_file.bin")
            
        print(f"Generating {target_size_mb}MB file...")
        target_size = target_size_mb * 1024 * 1024
        
        # Generate exactly 100MB of data
        with open(output_path, 'wb') as f:
            written = 0
            while written < target_size:
                remaining = target_size - written
                # Write in 1MB chunks to match our chunking strategy
                chunk_size = min(self.chunk_size, remaining)
                chunk = secrets.token_bytes(chunk_size)
                f.write(chunk)
                written += len(chunk)
        
        actual_size = os.path.getsize(output_path)
        print(f"Generated file: {output_path} ({actual_size} bytes, {actual_size / (1024*1024):.2f} MB)")
        return output_path
    
    def calculate_sha256(self, file_path):
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def zip_file(self, input_path, output_path=None):
        """Compress file using zip"""
        if output_path is None:
            output_path = os.path.join(self.root_dir, "compressed_file.zip")
            
        print(f"Compressing {input_path} to {output_path}...")
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(input_path, os.path.basename(input_path))
        
        print(f"Zipped file size: {os.path.getsize(output_path)} bytes")
        return output_path
    
    def generate_node_id(self):
        """Generate a random node ID"""
        return secrets.token_hex(8)
    
    def split_file_directly(self, input_file_path, output_dir=None):
        """Split the original 100MB file directly into 100 chunks of 1MB each"""
        if output_dir is None:
            output_dir = os.path.join(self.root_dir, "chunks")
            
        print("Splitting 100MB file directly into 100 chunks...")
        
        # Read the entire file
        with open(input_file_path, 'rb') as f:
            file_data = f.read()
        
        file_size = len(file_data)
        expected_size = 100 * 1024 * 1024  # 100 MB
        
        if file_size != expected_size:
            print(f"Warning: File size is {file_size} bytes, expected {expected_size} bytes")
        
        # Generate metadata for exactly 100 chunks
        nodes = []
        total_chunks = 100
        chunk_size = self.chunk_size
        
        # Pre-generate all node IDs to ensure consistency
        node_ids = [self.generate_node_id() for _ in range(total_chunks)]
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        for i in range(total_chunks):
            start_idx = i * chunk_size
            end_idx = min((i + 1) * chunk_size, file_size)
            chunk_data = file_data[start_idx:end_idx]
            
            # Determine previous and next node IDs
            prev_node_id = node_ids[i-1] if i > 0 else None
            next_node_id = node_ids[i+1] if i < total_chunks - 1 else None
            
            # Generate domains (chunk filenames)
            domains = [f"chunk_{i:02d}.dat"]
            
            # Create node
            node = {
                "node_id": node_ids[i],
                "prev": prev_node_id,
                "next": next_node_id,
                "permit": {
                    "algo": "AES-GCM",
                    "key_hex": secrets.token_hex(32),
                    "used_bytes": len(chunk_data),
                    "max_bytes": 64 * 1024 * 1024 * 1024,  # 64 GB
                    "domains": domains,
                    "revoked": False,
                    "timestamp": 4313094.01 + i
                }
            }
            
            nodes.append(node)
            
            # Save chunk
            chunk_path = os.path.join(output_dir, domains[0])
            with open(chunk_path, 'wb') as f:
                f.write(chunk_data)
            
            print(f"Created chunk {i+1}/{total_chunks}: {domains[0]} ({len(chunk_data)} bytes)")
        
        # Save metadata to JSON file
        metadata = {
            "total_size": file_size,
            "original_sha256": self.calculate_sha256(input_file_path),
            "chunk_count": total_chunks,
            "chunk_size": chunk_size,
            "file_size_mb": 100,
            "nodes": nodes
        }
        
        metadata_path = os.path.join(output_dir, "metadata.json")
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"Metadata saved to {metadata_path}")
        
        # Also save a separate detailed nodes JSON file
        nodes_metadata_path = os.path.join(self.root_dir, "chunks_metadata_detailed.json")
        with open(nodes_metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"Detailed metadata saved to {nodes_metadata_path}")
        return metadata_path

    def reassemble_from_chunks(self, chunks_dir=None, output_file_path=None):
        """Reassemble chunks using metadata"""
        if chunks_dir is None:
            chunks_dir = os.path.join(self.root_dir, "chunks")
        if output_file_path is None:
            output_file_path = os.path.join(self.root_dir, "reassembled_file.bin")
            
        print("Reassembling chunks...")
        
        # Load metadata
        metadata_path = os.path.join(chunks_dir, "metadata.json")
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        # Use the node order from metadata
        assembled_data = bytearray()
        nodes = metadata["nodes"]
        
        print(f"Found {len(nodes)} nodes in metadata")
        
        # Iterate through nodes in the order they appear in the array
        for i, node in enumerate(nodes):
            chunk_filename = node["permit"]["domains"][0]
            chunk_path = os.path.join(chunks_dir, chunk_filename)
            
            if not os.path.exists(chunk_path):
                raise FileNotFoundError(f"Chunk file not found: {chunk_path}")
            
            with open(chunk_path, 'rb') as f:
                chunk_data = f.read()
            
            assembled_data.extend(chunk_data)
            print(f"Added chunk {i+1}/{len(nodes)}: {chunk_filename} ({len(chunk_data)} bytes)")
        
        # Save reassembled file
        with open(output_file_path, 'wb') as f:
            f.write(assembled_data)
        
        # Verify size
        if len(assembled_data) != metadata["total_size"]:
            raise ValueError(f"Size mismatch: expected {metadata['total_size']}, got {len(assembled_data)}")
        
        # Verify SHA256
        reassembled_sha256 = self.calculate_sha256(output_file_path)
        if reassembled_sha256 != metadata["original_sha256"]:
            raise ValueError(f"SHA256 mismatch! Expected {metadata['original_sha256']}, got {reassembled_sha256}")
        
        print(f"Successfully reassembled {output_file_path}")
        print(f"SHA256 verified: {reassembled_sha256}")
        
        return output_file_path
    
    def verify_final_integrity(self, original_file, final_file):
        """Verify SHA256 of original and final files match"""
        original_hash = self.calculate_sha256(original_file)
        final_hash = self.calculate_sha256(final_file)
        
        print(f"\n=== INTEGRITY VERIFICATION ===")
        print(f"Original file SHA256: {original_hash}")
        print(f"Final file SHA256:    {final_hash}")
        
        if original_hash == final_hash:
            print("✅ SUCCESS: Files are identical! Data integrity verified.")
            return True
        else:
            print("❌ FAILURE: Files are different! Data corruption detected.")
            return False
    
    def display_chunk_info(self):
        """Display information about the generated chunks"""
        chunks_dir = os.path.join(self.root_dir, "chunks")
        metadata_path = os.path.join(chunks_dir, "metadata.json")
        
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        print(f"\n=== CHUNK INFORMATION ===")
        print(f"Total chunks: {metadata['chunk_count']}")
        print(f"Chunk size: {metadata['chunk_size']} bytes")
        print(f"Total file size: {metadata['total_size']} bytes")
        print(f"Expected chunks: 100")
        
        # Count actual chunk files
        chunk_files = [f for f in os.listdir(chunks_dir) if f.startswith('chunk_') and f.endswith('.dat')]
        print(f"Actual chunk files: {len(chunk_files)}")
        
        # Display first few nodes as example
        print(f"\nFirst 3 nodes example:")
        for i in range(min(3, len(metadata['nodes']))):
            node = metadata['nodes'][i]
            print(f"Node {i}: {node['node_id']} -> {node['permit']['domains'][0]}")
        
        # Display last few nodes as example
        print(f"\nLast 3 nodes example:")
        for i in range(max(0, len(metadata['nodes'])-3), len(metadata['nodes'])):
            node = metadata['nodes'][i]
            print(f"Node {i}: {node['node_id']} -> {node['permit']['domains'][0]}")

def main():
    # Use current directory as root
    root_dir = '.'
    manager = FileChunkManager(root_dir)
    
    print(f"Working in directory: {os.path.abspath(root_dir)}")
    
    try:
        # Step 1: Generate exactly 100MB file
        print("\n=== STEP 1: Generating 100MB file ===")
        original_file = manager.generate_large_file(target_size_mb=100)
        original_sha256 = manager.calculate_sha256(original_file)
        print(f"Original file SHA256: {original_sha256}")
        
        # Step 2: Split directly into 100 chunks of 1MB each
        print("\n=== STEP 2: Splitting into 100 chunks ===")
        chunks_dir = os.path.join(root_dir, "chunks")
        metadata_path = manager.split_file_directly(original_file, chunks_dir)
        
        # Step 3: Reassemble from chunks
        print("\n=== STEP 3: Reassembling from chunks ===")
        reassembled_file = manager.reassemble_from_chunks(chunks_dir)
        
        # Step 4: Final integrity check
        print("\n=== STEP 4: Verifying integrity ===")
        manager.verify_final_integrity(original_file, reassembled_file)
        
        # Display chunk information
        manager.display_chunk_info()
        
        # List all generated files
        print(f"\n=== GENERATED FILES ===")
        for item in os.listdir(root_dir):
            item_path = os.path.join(root_dir, item)
            if os.path.isdir(item_path):
                size = sum(os.path.getsize(os.path.join(item_path, f)) for f in os.listdir(item_path) if os.path.isfile(os.path.join(item_path, f)))
                file_count = len([f for f in os.listdir(item_path) if os.path.isfile(os.path.join(item_path, f))])
                print(f"📁 {item}/ ({file_count} files, {size} bytes)")
            else:
                print(f"📄 {item} ({os.path.getsize(item_path)} bytes)")
        
        # Verify we have exactly 100 chunks
        chunks_dir = os.path.join(root_dir, "chunks")
        chunk_files = [f for f in os.listdir(chunks_dir) if f.startswith('chunk_') and f.endswith('.dat')]
        print(f"\n✅ VERIFICATION: Found {len(chunk_files)} chunk files (expected: 100)")
        
        if len(chunk_files) == 100:
            print("🎉 SUCCESS: Exactly 100 chunks created!")
        else:
            print(f"⚠️  WARNING: Expected 100 chunks, but found {len(chunk_files)}")
                
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

"""
Working in directory: /content

=== STEP 1: Generating 100MB file ===
Generating 100MB file...
Generated file: ./original_large_file.bin (104857600 bytes, 100.00 MB)
Original file SHA256: e7dfd9de761c372bc7f9dd85927e95cde0e985ed2c11221b601eafe2c17a62f7

=== STEP 2: Splitting into 100 chunks ===
Splitting 100MB file directly into 100 chunks...
Created chunk 1/100: chunk_00.dat (1048576 bytes)
Created chunk 2/100: chunk_01.dat (1048576 bytes)
:
Created chunk 100/100: chunk_99.dat (1048576 bytes)
Metadata saved to ./chunks/metadata.json
Detailed metadata saved to ./chunks_metadata_detailed.json

=== STEP 3: Reassembling from chunks ===
Reassembling chunks...
Found 100 nodes in metadata
Added chunk 1/100: chunk_00.dat (1048576 bytes)
Added chunk 2/100: chunk_01.dat (1048576 bytes)
:
Added chunk 100/100: chunk_99.dat (1048576 bytes)
Successfully reassembled ./reassembled_file.bin
SHA256 verified: e7dfd9de761c372bc7f9dd85927e95cde0e985ed2c11221b601eafe2c17a62f7

=== STEP 4: Verifying integrity ===

=== INTEGRITY VERIFICATION ===
Original file SHA256: e7dfd9de761c372bc7f9dd85927e95cde0e985ed2c11221b601eafe2c17a62f7
Final file SHA256:    e7dfd9de761c372bc7f9dd85927e95cde0e985ed2c11221b601eafe2c17a62f7
✅ SUCCESS: Files are identical! Data integrity verified.

=== CHUNK INFORMATION ===
Total chunks: 100
Chunk size: 1048576 bytes
Total file size: 104857600 bytes
Expected chunks: 100
Actual chunk files: 100

First 3 nodes example:
Node 0: 2879ffb4608e96a3 -> chunk_00.dat
Node 1: 36e6b718d15d33ad -> chunk_01.dat
Node 2: cf363aa5daad61e0 -> chunk_02.dat

Last 3 nodes example:
Node 97: 1ed131a227792cc1 -> chunk_97.dat
Node 98: 69d2d53fbf41cd2c -> chunk_98.dat
Node 99: 763f9368a89bb4cc -> chunk_99.dat

=== GENERATED FILES ===
📁 .config/ (8 files, 24762 bytes)
📄 reassembled_file.bin (104857600 bytes)
📁 chunks/ (101 files, 104901577 bytes)
📁 extracted/ (1 files, 104857600 bytes)
📄 compressed_file.zip (32347007 bytes)
📄 chunks_metadata_detailed.json (43977 bytes)
📄 reassembled.zip (32347007 bytes)
📄 original_large_file.bin (104857600 bytes)
📁 sample_data/ (6 files, 56823553 bytes)

✅ VERIFICATION: Found 100 chunk files (expected: 100)
🎉 SUCCESS: Exactly 100 chunks created!
"""