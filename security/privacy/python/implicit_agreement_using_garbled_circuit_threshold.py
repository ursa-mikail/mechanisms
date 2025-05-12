"""
Secure Feature Evaluation, where a client's private feature is used in a decision (e.g. node in a decision tree) without revealing the feature itself — using encryption and logic evaluation.

Simulate a decision node:
	feature > threshold

Instead of revealing the feature to the server (which holds the model), let the server evaluate the logic securely using double encryption — like in the logic gate example.

Scenario:
Client owns private input feature = 7

Server owns decision rule feature > 5

They want to evaluate this condition without sharing the raw feature or the model rule directly.

🔍 What Makes It Privacy-Preserving?
- Server never sees private_feature
- Client never learns the full decision function — only gets the evaluation result for their input
- The key distribution ensures that only authorized evaluations can be decrypted
- Could be expanded to:
	- Obfuscate thresholds
	- Obfuscate the full decision path (e.g. in random forests or XGBoost)

💡 Real Use Cases
- Healthcare AI: Evaluate medical risk factors privately
- Finance ML: Approve transactions or loans without exposing the user's full financial data
- Federated Learning: Support logic-based validation of local models before aggregation
"""

from cryptography.fernet import Fernet
import random
import binascii

# --- Step 1: Setup ---

# Decision rule: feature > 5
threshold = 5

# Client's private feature (not revealed)
private_feature = 7

# Server builds the truth table for "feature > threshold"
def evaluate_threshold(threshold):
    table = {}
    for i in range(0, 16):  # assuming 4-bit features [0-15]
        result = int(i > threshold)
        table[i] = result
    return table

truth_table = evaluate_threshold(threshold)

# Generate a unique encryption key per input value
keys = {i: Fernet.generate_key() for i in truth_table.keys()}

# Server encrypts outputs (yes/no) with the corresponding keys
encrypted_results = {
    i: Fernet(keys[i]).encrypt(str(result).encode())
    for i, result in truth_table.items()
}

# --- Step 2: Client side ---

# Client holds their feature (7) and gets only the encrypted result for that key
client_key = keys[private_feature]
client_ciphertext = encrypted_results[private_feature]

# --- Step 3: Client decrypts their result ---

decrypted_result = Fernet(client_key).decrypt(client_ciphertext).decode()

print(f"[Client] Feature: {private_feature}")
print(f"[Client] Evaluation (feature > {threshold}): {decrypted_result}")

"""
[Client] Feature: 7
[Client] Evaluation (feature > 5): 1
"""