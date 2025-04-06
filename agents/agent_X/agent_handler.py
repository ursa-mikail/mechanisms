import base64
import os
import subprocess
import stat
from cryptography.fernet import Fernet

class AgentHandler:
    def __init__(self):
        self.encrypted_data = None
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def load_and_encrypt(self, filename='agent_X'):
        with open(filename, 'rb') as f:
            binary_data = f.read()

        b64_data = base64.b64encode(binary_data)
        self.encrypted_data = self.cipher.encrypt(b64_data)

        os.remove(filename)
        print(f"[+] {filename} encrypted and removed.")

    def run(self):
        print("Choose your option:\n1. status\n2. trapdoor\n3. quit")
        choice = input("Enter option: ").strip().lower()
        if choice == "trapdoor":
            self.order_strike("go_go_gadget_x")
        else:
            print("[*] Standing by...")

    def order_strike(self, passcode):
        if passcode != "go_go_gadget_x":
            print("[!] Incorrect passcode.")
            return

        print("[🔓] Passcode accepted. Preparing to execute payload...")

        decrypted_b64 = self.cipher.decrypt(self.encrypted_data)
        binary_data = base64.b64decode(decrypted_b64)

        restored_file = "agent_X_restored"
        with open(restored_file, 'wb') as f:
            f.write(binary_data)

        # Make it executable
        st = os.stat(restored_file)
        os.chmod(restored_file, st.st_mode | stat.S_IEXEC)

        print(f"[⚡] Executing {restored_file}...\n")
        subprocess.run([f"./{restored_file}"])

        os.remove(restored_file)
        print(f"[🧹] {restored_file} executed and removed.")

# Example usage
if __name__ == "__main__":
    handler = AgentHandler()

    if os.path.exists("agent_X"):
        handler.load_and_encrypt()
        print("agent_X loaded and ready to go.")
    else:
        print("[-] agent_X not found. Skipping encryption.")

    handler.run()
