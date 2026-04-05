import json
import hmac
import hashlib
import base64
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class SecureChannel:
    """
    This version uses AES for encryption and HMAC-SHA256 for integrity.

    We keep encryption and MAC separate to match the project requirement
    of using two derived keys.
    """

    def __init__(self, enc_key: bytes, mac_key: bytes):
        # AES requires key sizes of 16, 24, or 32 bytes
        self.enc_key = enc_key[:32]
        self.mac_key = mac_key

    def _pad(self, data: bytes) -> bytes:
        """
        Apply PKCS7 padding so plaintext fits AES block size (16 bytes).
        """
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data: bytes) -> bytes:
        """
        Remove PKCS7 padding after decryption.
        """
        pad_len = data[-1]
        return data[:-pad_len]

    def encrypt_payload(self, payload: dict) -> str:
        """
        Encrypt payload using AES-CBC.

        We generate a random IV for each message.
        """
        plaintext = json.dumps(payload).encode("utf-8")
        padded = self._pad(plaintext)

        iv = os.urandom(16)

        cipher = Cipher(
            algorithms.AES(self.enc_key),
            modes.CBC(iv),
            backend=default_backend()
        )

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        # prepend IV so receiver can decrypt
        combined = iv + ciphertext
        return base64.b64encode(combined).decode("utf-8")

    def decrypt_payload(self, encoded_ciphertext: str) -> dict:
        """
        Decrypt AES-CBC payload.
        """
        combined = base64.b64decode(encoded_ciphertext.encode("utf-8"))

        iv = combined[:16]
        ciphertext = combined[16:]

        cipher = Cipher(
            algorithms.AES(self.enc_key),
            modes.CBC(iv),
            backend=default_backend()
        )

        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        plaintext = self._unpad(padded)
        return json.loads(plaintext.decode("utf-8"))

    def create_mac(self, ciphertext: str, seq: int) -> str:
        """
        MAC is computed over sequence number + ciphertext.
        """
        message = f"{seq}|{ciphertext}"
        return hmac.new(
            self.mac_key,
            message.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

    def verify_mac(self, ciphertext: str, seq: int, received_mac: str) -> bool:
        expected = self.create_mac(ciphertext, seq)
        return hmac.compare_digest(expected, received_mac)

    def wrap_secure_message(self, payload: dict, seq: int) -> dict:
        """
        Encrypt + MAC wrapper.
        """
        ciphertext = self.encrypt_payload(payload)
        mac = self.create_mac(ciphertext, seq)

        return {
            "type": "secure",
            "seq": seq,
            "payload": ciphertext,
            "mac": mac
        }

    def unwrap_secure_message(self, message: dict) -> dict:
        """
        Verify MAC first, then decrypt.
        """
        seq = message.get("seq")
        ciphertext = message.get("payload")
        received_mac = message.get("mac")

        if not self.verify_mac(ciphertext, seq, received_mac):
            raise ValueError("MAC verification failed.")

        return self.decrypt_payload(ciphertext)