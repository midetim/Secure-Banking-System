import hmac
import hashlib


class KeyDerivation:
    """
    This class derives separate working keys from the session Master Secret.

    The project requires one key for encryption and another key for message
    authentication. We derive them independently so they are not reused
    across different security purposes.
    """

    def __init__(self, master_secret: str):
        # The Master Secret is stored as bytes because HMAC expects bytes.
        self.master_secret = master_secret.encode("utf-8")

    def _derive(self, label: str) -> bytes:
        """
        Derive a key using HMAC-SHA256 over a small label.

        The label makes each derived key purpose-specific.
        For example, using 'enc' and 'mac' gives us two different keys
        even though they come from the same Master Secret.
        """
        return hmac.new(
            self.master_secret,
            label.encode("utf-8"),
            hashlib.sha256
        ).digest()

    def derive_encryption_key(self) -> bytes:
        """
        Derive the encryption key.
        """
        return self._derive("enc")

    def derive_mac_key(self) -> bytes:
        """
        Derive the MAC key.
        """
        return self._derive("mac")