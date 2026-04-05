import os
import json
import base64
import threading
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AuditLogger:
    """
    This class handles encrypted audit logging for the banking server.

    Each log entry is written as its own encrypted record so that:
    - the file can be appended to easily
    - records stay separate
    - the log can be decrypted later for demo or inspection

    The log records the customer ID, the action taken, and the timestamp.
    """

    def __init__(self, log_file_path: str, log_key: bytes):
        self.log_file_path = log_file_path
        self.lock = threading.Lock()

        # AES accepts 16, 24, or 32 byte keys.
        # We trim to 32 bytes so this works cleanly with AES-256.
        self.log_key = log_key[:32]

        log_dir = os.path.dirname(self.log_file_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        # Make sure the file exists so appending later is simple.
        if not os.path.exists(self.log_file_path):
            with open(self.log_file_path, "w", encoding="utf-8") as f:
                pass

    def _pad(self, data: bytes) -> bytes:
        """
        Apply PKCS7 padding so the plaintext fits the AES block size.
        """
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data: bytes) -> bytes:
        """
        Remove PKCS7 padding after decryption.
        """
        pad_len = data[-1]
        return data[:-pad_len]

    def _encrypt_entry(self, entry: dict) -> str:
        """
        Encrypt a single log entry.

        We generate a fresh IV for every log record so repeated actions do not
        produce repeated ciphertext.
        """
        plaintext = json.dumps(entry).encode("utf-8")
        padded = self._pad(plaintext)

        iv = os.urandom(16)

        cipher = Cipher(
            algorithms.AES(self.log_key),
            modes.CBC(iv),
            backend=default_backend()
        )

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        combined = iv + ciphertext
        return base64.b64encode(combined).decode("utf-8")

    def _decrypt_entry(self, encoded_entry: str) -> dict:
        """
        Decrypt one base64-encoded audit log record back into a dictionary.
        """
        combined = base64.b64decode(encoded_entry.encode("utf-8"))
        iv = combined[:16]
        ciphertext = combined[16:]

        cipher = Cipher(
            algorithms.AES(self.log_key),
            modes.CBC(iv),
            backend=default_backend()
        )

        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = self._unpad(padded)

        return json.loads(plaintext.decode("utf-8"))

    def log_action(self, customer_id: str, action: str) -> None:
        """
        Build an audit entry and append the encrypted version to the log file.

        We lock writes so multiple client threads do not corrupt the log.
        """
        entry = {
            "customer_id": customer_id,
            "action": action,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        encrypted_entry = self._encrypt_entry(entry)

        with self.lock:
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(encrypted_entry + "\n")

    def read_decrypted_logs(self) -> list[dict]:
        """
        Read the log file and return all entries in decrypted form.

        This is useful for testing and for your demo when the TA wants to see
        what the server recorded.
        """
        entries = []

        if not os.path.exists(self.log_file_path):
            return entries

        with self.lock:
            with open(self.log_file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        entry = self._decrypt_entry(line)
                        entries.append(entry)
                    except Exception as e:
                        entries.append({
                            "error": f"Failed to decrypt log entry: {str(e)}"
                        })

        return entries