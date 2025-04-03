
#!pip install faker
#!pip install pycryptodome
from faker import Faker
from datetime import datetime
import time
import os
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

fake = Faker()

# Directory to store encrypted logs
LOG_DIR = 'user_logs'
os.makedirs(LOG_DIR, exist_ok=True)

# Helper functions for AES encryption
def pad(data):
    return data + (16 - len(data) % 16) * chr(16 - len(data) % 16)

def unpad(data):
    return data[:-ord(data[-1])]

def encrypt(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data).encode('utf-8'))
    return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')

def decrypt(key, enc_data):
    enc = base64.b64decode(enc_data)
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]).decode('utf-8'))

# Register users and assign AES keys
def register_users(n):
    users = {}
    for _ in range(n):
        user_id = fake.uuid4()
        aes_key = get_random_bytes(16)  # 128-bit AES key
        users[user_id] = aes_key
        print(f"Registered User: {user_id}, AES Key: {aes_key.hex()}")
    return users

# Log user activity
def log_user_activity(user_id, aes_key, activity):
    timestamp_linux = int(time.time())
    timestamp_human = datetime.now().strftime('%Y-%m-%d_%H%M_%S')
    log_entry = json.dumps({
        'user_id': user_id,
        'activity': activity,
        'timestamp_linux': timestamp_linux,
        'timestamp_human': timestamp_human
    })

    encrypted_log = encrypt(aes_key, log_entry)

    with open(os.path.join(LOG_DIR, f"{user_id}.log"), 'a') as f:
        f.write(encrypted_log + '\n')

    print(f"Logged activity for {user_id}: {activity}")

# Access logs for a specific user
def access_logs(user_id, aes_key):
    log_file = os.path.join(LOG_DIR, f"{user_id}.log")
    if not os.path.exists(log_file):
        print("No logs available for this user.")
        return

    with open(log_file, 'r') as f:
        for line in f:
            try:
                decrypted_log = decrypt(aes_key, line.strip())
                print(decrypted_log)
            except Exception as e:
                print("Error decrypting log:", e)

# Example Usage
if __name__ == '__main__':
    num_users = 5
    users = register_users(num_users)

    # Simulate user polling and logging
    for user_id, aes_key in users.items():
        log_user_activity(user_id, aes_key, fake.sentence())

    # Access logs for a specific user
    target_user = list(users.keys())[0]
    print(f"\nAccessing logs for user: {target_user}")
    access_logs(target_user, users[target_user])

    for i in range(0, num_users):
        target_user = list(users.keys())[i]
        print(f"\nAccessing logs for user {i}: {target_user}")
        access_logs(target_user, users[target_user])


"""
Registered User: 3d37ac2d-2a11-4af3-ac75-fc7366696477, AES Key: aa3ec11d2c735f812ff2550c68d2853e
Registered User: 7c8d1694-5259-4408-b376-86449ae47760, AES Key: cc230741f81b77883632c911f647069f
Registered User: 80ace321-56f3-4ac9-8626-4b53f7395720, AES Key: 0425181ad9d2d52d6c679b14b7e4e352
Registered User: fe130141-b554-4b4e-9961-12879764ff30, AES Key: dae8c54c0b20cc616cb849234364d960
Registered User: 23cc4909-0e0b-493d-ad07-e30a238c5cea, AES Key: 3a039397337393e1a4463af113d96667
Logged activity for 3d37ac2d-2a11-4af3-ac75-fc7366696477: Reason indeed why decide how about.
Logged activity for 7c8d1694-5259-4408-b376-86449ae47760: Fear also product compare author.
Logged activity for 80ace321-56f3-4ac9-8626-4b53f7395720: Me product successful third.
Logged activity for fe130141-b554-4b4e-9961-12879764ff30: Up ready majority various shake trouble understand.
Logged activity for 23cc4909-0e0b-493d-ad07-e30a238c5cea: Writer state pressure morning husband.

Accessing logs for user: 3d37ac2d-2a11-4af3-ac75-fc7366696477
{"user_id": "3d37ac2d-2a11-4af3-ac75-fc7366696477", "activity": "Reason indeed why decide how about.", "timestamp_linux": 1741980881, "timestamp_human": "2025-03-14_1934_41"}

Accessing logs for user 0: 3d37ac2d-2a11-4af3-ac75-fc7366696477
{"user_id": "3d37ac2d-2a11-4af3-ac75-fc7366696477", "activity": "Reason indeed why decide how about.", "timestamp_linux": 1741980881, "timestamp_human": "2025-03-14_1934_41"}

Accessing logs for user 1: 7c8d1694-5259-4408-b376-86449ae47760
{"user_id": "7c8d1694-5259-4408-b376-86449ae47760", "activity": "Fear also product compare author.", "timestamp_linux": 1741980881, "timestamp_human": "2025-03-14_1934_41"}

Accessing logs for user 2: 80ace321-56f3-4ac9-8626-4b53f7395720
{"user_id": "80ace321-56f3-4ac9-8626-4b53f7395720", "activity": "Me product successful third.", "timestamp_linux": 1741980881, "timestamp_human": "2025-03-14_1934_41"}

Accessing logs for user 3: fe130141-b554-4b4e-9961-12879764ff30
{"user_id": "fe130141-b554-4b4e-9961-12879764ff30", "activity": "Up ready majority various shake trouble understand.", "timestamp_linux": 1741980881, "timestamp_human": "2025-03-14_1934_41"}

Accessing logs for user 4: 23cc4909-0e0b-493d-ad07-e30a238c5cea
{"user_id": "23cc4909-0e0b-493d-ad07-e30a238c5cea", "activity": "Writer state pressure morning husband.", "timestamp_linux": 1741980881, "timestamp_human": "2025-03-14_1934_41"}
""""