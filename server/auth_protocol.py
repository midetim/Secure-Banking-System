import hmac
import hashlib
import secrets
from typing import Optional


class AuthProtocol:
    """
    This class handles the authenticated key distribution handshake.

    We assume the client and server already share a long-term secret key.
    The handshake uses that key plus fresh nonces to authenticate both sides
    and create a new Master Secret for the current session.
    """

    def __init__(self, shared_key: str):
        # Store the pre-shared key as bytes because HMAC works on bytes.
        self.shared_key = shared_key.encode("utf-8")

    def generate_nonce(self, length: int = 16) -> str:
        """
        Generate a random nonce for the handshake.

        We use a hex string because it is easy to send in JSON and easy to read
        while testing.
        """
        return secrets.token_hex(length)

    def _hmac_hex(self, message: str) -> str:
        """
        Compute HMAC-SHA256 over the given message using the shared key.

        This is used to prove that one side knows the shared key without
        sending the key itself.
        """
        return hmac.new(
            self.shared_key,
            message.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

    def create_server_proof(self, username: str, client_nonce: str, server_nonce: str) -> str:
        """
        Build the proof that the server sends to the client.

        The proof ties together:
        - the user's identity
        - the client nonce
        - the server nonce

        This helps make the response specific to this user and this session,
        instead of something that could be replayed later.
        """
        message = f"server|{username}|{client_nonce}|{server_nonce}"
        return self._hmac_hex(message)

    def verify_server_proof(self, username: str, client_nonce: str, server_nonce: str, proof: str) -> bool:
        """
        Verify the server's proof on the client side.
        """
        expected = self.create_server_proof(username, client_nonce, server_nonce)
        return hmac.compare_digest(expected, proof)

    def create_client_proof(self, username: str, client_nonce: str, server_nonce: str) -> str:
        """
        Build the proof that the client sends back to the server.

        This proves the client also knows the shared key and saw the
        server's fresh nonce.
        """
        message = f"client|{username}|{client_nonce}|{server_nonce}"
        return self._hmac_hex(message)

    def verify_client_proof(self, username: str, client_nonce: str, server_nonce: str, proof: str) -> bool:
        """
        Verify the client's proof on the server side.
        """
        expected = self.create_client_proof(username, client_nonce, server_nonce)
        return hmac.compare_digest(expected, proof)

    def derive_master_secret(self, username: str, client_nonce: str, server_nonce: str) -> str:
        """
        Derive a fresh Master Secret for this session.

        We combine:
        - username
        - client nonce
        - server nonce
        - shared key

        The result is hashed to produce a fixed-length session secret.
        This gives us a fresh secret for every successful handshake.
        """
        material = f"{username}|{client_nonce}|{server_nonce}".encode("utf-8")
        return hmac.new(self.shared_key, material, hashlib.sha256).hexdigest()