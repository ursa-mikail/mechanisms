# Stealth Tool Mimick
Mimics a spy tool with a memory-hoarding, file-destroying encryption step, plus a trapdoor-activated execution flow.

Caveat:
This is only a `command & control implant simulation`, red-team tool, or a basic secure remote job runner.
Do NOT use for actual deployment.

- In-memory key+payload storage: Keeps things transient and clean.
- Base64 + Fernet: Simple but secure enough for many use cases; easy to reverse reliably.
- Deletes the original: Great for minimizing footprints — nice opsec touch.
- Executable handling: Adapts seamlessly to binary payloads.
- Trapdoor flow: User prompt gives it that “agent activation” vibe.
- Self-cleaning: Removes restored payload after execution, leaving little behind. 

../target/debug/agent_X

```
Prints: "i can hoard memory, but i am just spitting out files"

Creates files named file11.txt to file22.txt

Each file contains a timestamp in the format yyyy-mm.dd_hhmm

Randomly picks one of those files and reads its content

Prints: read file xx.txt and the contents is <timestamp>
```

This should be store as an object with encapsulated load (not demonstrated here, but in object signing).

 ```
Python agent:

1. Reads executable called agent_X.

2. Serializes its contents to base64.

3. Generates a symmetric encryption key.

4. Encrypts the base64 content using the key.

5. Deletes the original agent_X executable.

6. Stores the ciphered base64 and key inside the object.

7. When given passcode = "go_go_gadget_x", it:

- Decrypts the ciphered base64
- Reconstructs the original binary (agent_X)
- Writes agent_X temporarily and executes it (Runs it via subprocess).
- Removes the file after execution.

🔐 Trapdoor-like mechanism:

- Calling run() prompts the user with options, one of which is "trapdoor" that triggers the decryption and execution.
 ```

 To test agent_X independently:
 ```
echo -e '#!/bin/bash\necho "🚀 Agent deployed."' > agent_X
chmod +x agent_X
 ```

### 🔐 Optional Improvements
Feature						| Idea
Passcode obfuscation		| Use a hash instead of plaintext check (e.g., SHA256).
In-memory exec (advanced)	| Use ctypes or mmap to avoid writing the binary to disk.
Multi-pass options			| Add decoy options in run() to hide the trapdoor in plain sight.
Log to memory only			| Add an in-memory action log instead of printing to stdout.
Time/host lock				| Only allow decryption on certain hosts or at specific times.
