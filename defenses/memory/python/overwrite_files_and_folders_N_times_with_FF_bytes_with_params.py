import os
import sys

def overwrite_file_with_ff(path):
    try:
        with open(path, 'r+b') as f:
            size = os.path.getsize(path)
            chunk_size = 4096
            ff_chunk = b'\xff' * chunk_size
            written = 0
            while written < size:
                to_write = min(chunk_size, size - written)
                f.write(ff_chunk[:to_write])
                written += to_write
        print(f"Overwritten: {path}")
    except Exception as e:
        print(f"Error overwriting {path}: {e}")

def overwrite_folder(folder_path):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            full_path = os.path.join(root, file)
            overwrite_file_with_ff(full_path)

def secure_overwrite(path):
    if os.path.isfile(path):
        overwrite_file_with_ff(path)
    elif os.path.isdir(path):
        overwrite_folder(path)
    else:
        print(f"Unsupported type: {path}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python overwrite_files_and_folders_N_times_with_FF_bytes_with_params.py <file-or-folder>")
        sys.exit(1)
    secure_overwrite(sys.argv[1])

"""
python3 overwrite_files_and_folders_N_times_with_FF_bytes_with_params.py my_folder
# or
python3 overwrite_files_and_folders_N_times_with_FF_bytes_with_params.py sensitive_file.txt

💡 Notes
Uses b'\xff' (ones) to overwrite.
Works on files and folders, recursive for folders.
You can add multiple passes.

⚠️ Caution
Cannot guarantee secure erasure on SSDs or APFS due to hardware/filesystem-level behavior.
For those, consider full-disk encryption (e.g., FileVault) or secure erase tools at the disk level.

macOS includes the rm command with the -P option, which overwrites files before deleting them:
rm -P filename

🔍 shred -vzn 10 <filename> would securely shred a file by overwriting it 11 times (10 random, 1 zero).
-v: Verbose — Shows progress.
-z: Final overwrite with zeros — After random overwrites, writes zeros to hide shredding.
-n 10: Number of passes — Overwrites the file 10 times (plus one final zero pass because of -z).

✅ To securely delete everything inside a folder:
find my_folder -type f -exec shred -vzn 10 {} \; && rm -r my_folder

This command:
Finds all regular files in my_folder
Runs shred -vzn 10 on each file
Then deletes the folder structure after overwriting the files

## To overwrite with 0xFF
✅ Method 1: Use dd to overwrite with ones (0xFF)
dd if=/dev/zero ibs=1 count=$(stat -f%z filename) | tr '\0' '\377' | dd of=filename conv=notrunc

Explanation:
stat -f%z filename gets the size of the file in bytes.
tr '\0' '\377' replaces every 0 byte from /dev/zero with 0xFF (octal 377).
dd of=filename conv=notrunc writes back to the file without truncating.

✅ Method 2: Overwrite with ones using Python (safe & portable)
python3 -c "with open('filename', 'r+b') as f: f.write(b'\xff' * len(f.read()))"
This opens the file in binary read/write mode and overwrites its content with bytes of 0xFF.

🧪 Optional: Multiple passes
To do multiple passes of 0xFF overwrites:
for i in {1..3}; do
  python3 -c "with open('filename', 'r+b') as f: f.write(b'\xff' * len(f.read()))"
done

To overwrite all files inside a folder with 0xFF bytes (ones), recursively find every regular file, then overwrite each file with 0xFF data of the same size.

✅ One-Liner Using Python + find
find my_folder -type f -exec python3 -c "import sys, os; f=sys.argv[1]; s=os.path.getsize(f); open(f, 'r+b').write(b'\xff'*s)" {} \;

This Recursively finds all files under my_folder

For each file:
    - Gets its size
    - Overwrites it entirely with 0xFF

✅ Bash Loop Version (Clearer for editing)
for file in $(find my_folder -type f); do
  size=$(stat -f%z "$file")  # Use `stat -c%s` on Linux
  printf '\xff%.0s' $(seq 1 "$size") | dd of="$file" bs=1 count="$size" conv=notrunc status=none
done

⚠️ Limitations
This works for regular files only.
Does not handle symbolic links, special device files, or hard links specially.

May not be effective on:
    - APFS (copy-on-write)
    - SSDs (due to wear-leveling)
    - File systems that silently compress or snapshot


"""