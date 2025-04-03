import hmac
import hashlib
import json
import os

SECRET_KEY = b'supersecretkey'  # Change this for security
FILE_PATH = "signed_object.json"

def generate_object():
    """Generate an object with a random hex and a static string."""
    return {
        "random_hex": os.urandom(16).hex(),
        "static_string": "you should see this"
    }

def sign_object(obj):
    """Sign the object using HMAC-SHA256."""
    obj_json = json.dumps(obj, sort_keys=True).encode()
    return hmac.new(SECRET_KEY, obj_json, hashlib.sha256).hexdigest()

def store_object(obj, signature):
    """Store the object and its signature in a file."""
    with open(FILE_PATH, "w") as f:
        json.dump({"object": obj, "signature": signature}, f, indent=4)

def read_object():
    """Read the object and its signature from the file."""
    with open(FILE_PATH, "r") as f:
        data = json.load(f)
    return data["object"], data["signature"]

def verify_object(obj, signature):
    """Verify the object's integrity using HMAC."""
    expected_signature = sign_object(obj)
    return hmac.compare_digest(expected_signature, signature)

# Generate, sign, and store object
obj = generate_object()
signature = sign_object(obj)
store_object(obj, signature)

print("Before object destruction:", obj)
del obj

try:
    print("After object destruction:", obj)
except NameError:
    print("Object has been destroyed.")

# Read and verify object
retrieved_obj, retrieved_signature = read_object()
if verify_object(retrieved_obj, retrieved_signature):
    print("Verification successful:", retrieved_obj)
else:
    print("Verification failed!")

"""
Before object destruction: {'random_hex': '1b9a18e9339ad4332e059fa741d9b225', 'static_string': 'you should see this'}
Object has been destroyed.
Verification successful: {'random_hex': '1b9a18e9339ad4332e059fa741d9b225', 'static_string': 'you should see this'}
"""