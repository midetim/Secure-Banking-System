import socket
import json
import hmac
import hashlib
import secrets
import sys
import os

# Shared crypto modules live in server/ — import from there
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'server'))
from key_derivation import KeyDerivation
from secure_channel import SecureChannel

HOST = "127.0.0.1"
PORT = 5000
SHARED_KEY = "bank_shared_secret_2026"


class SecureClient:
    """
    Client-side API for the Secure Banking System.

    Usage:
        client = SecureClient()
        client.connect()
        client.login("alice", "pass123")
        client.handshake()
        client.deposit(500)
        client.balance()
        client.disconnect()
    """

    def __init__(self, host: str = HOST, port: int = PORT):
        self.host = host
        self.port = port
        self.sock = None
        self.username = None
        self.secure_channel = None
        self.seq = 0

    # ── Connection ───────────────────────────────────────────────────

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

    def disconnect(self):
        if self.sock:
            try:
                self._send({"type": "logout"})
            except Exception:
                pass
            self.sock.close()
            self.sock = None
        self.username = None
        self.secure_channel = None
        self.seq = 0

    def _send(self, payload: dict) -> dict:
        self.sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
        response = self.sock.recv(4096).decode("utf-8").strip()
        return json.loads(response)

    # ── Auth ─────────────────────────────────────────────────────────

    def register(self, username: str, password: str) -> dict:
        return self._send({
            "type": "register",
            "username": username,
            "password": password
        })

    def login(self, username: str, password: str) -> dict:
        result = self._send({
            "type": "login",
            "username": username,
            "password": password
        })
        if result.get("status") == "ok":
            self.username = username
        return result

    def handshake(self) -> bool:
        """
        Runs the two-step authenticated key distribution protocol.
        Both sides prove they know the shared key, then derive session keys.
        Returns True on success, False if anything fails.
        """
        client_nonce = secrets.token_hex(16)

        # Step 1 — send client nonce, receive server nonce + server proof
        resp = self._send({"type": "auth_start", "client_nonce": client_nonce})
        if resp.get("status") != "ok":
            return False

        server_nonce = resp["server_nonce"]
        server_proof = resp["server_proof"]

        # Verify server knows the shared key (mutual auth — server side)
        expected = hmac.new(
            SHARED_KEY.encode(),
            f"server|{self.username}|{client_nonce}|{server_nonce}".encode(),
            hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, server_proof):
            return False

        # Step 2 — send client proof back
        client_proof = hmac.new(
            SHARED_KEY.encode(),
            f"client|{self.username}|{client_nonce}|{server_nonce}".encode(),
            hashlib.sha256
        ).hexdigest()
        resp = self._send({"type": "auth_finish", "client_proof": client_proof})
        if resp.get("status") != "ok":
            return False

        # Derive session keys from Master Secret (same computation as server)
        master_secret = hmac.new(
            SHARED_KEY.encode(),
            f"{self.username}|{client_nonce}|{server_nonce}".encode(),
            hashlib.sha256
        ).hexdigest()
        kdf = KeyDerivation(master_secret)
        self.secure_channel = SecureChannel(kdf.derive_encryption_key(), kdf.derive_mac_key())
        self.seq = 0
        return True

    # ── Transactions ─────────────────────────────────────────────────

    def _secure_request(self, payload: dict) -> dict:
        """Wrap payload in AES+HMAC, send, verify and decrypt response."""
        self.seq += 1
        wrapped = self.secure_channel.wrap_secure_message(payload, seq=self.seq)
        response = self._send(wrapped)
        return self.secure_channel.unwrap_secure_message(response)

    def deposit(self, amount: float) -> dict:
        return self._secure_request({"action": "deposit", "amount": amount})

    def withdraw(self, amount: float) -> dict:
        return self._secure_request({"action": "withdraw", "amount": amount})

    def balance(self) -> dict:
        return self._secure_request({"action": "balance"})
