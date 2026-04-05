
import socket
import json
import hmac
import hashlib
import secrets
from key_derivation import KeyDerivation
from secure_channel import SecureChannel

HOST = "ur ip address here"
PORT = 5000
SHARED_KEY = "bank_shared_secret_2026"


def send_request(sock: socket.socket, payload: dict) -> dict:
    sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
    response = sock.recv(4096).decode("utf-8").strip()
    return json.loads(response)


def create_client_proof(username: str, client_nonce: str, server_nonce: str) -> str:
    """
    Recreate the same proof logic used by the server.
    """
    message = f"client|{username}|{client_nonce}|{server_nonce}"
    return hmac.new(
        SHARED_KEY.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def verify_server_proof(username: str, client_nonce: str, server_nonce: str, proof: str) -> bool:
    """
    Verify that the server knows the shared key and is responding to this
    exact handshake.
    """
    message = f"server|{username}|{client_nonce}|{server_nonce}"
    expected = hmac.new(
        SHARED_KEY.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, proof)


def derive_master_secret(username: str, client_nonce: str, server_nonce: str) -> str:
    """
    Derive the same Master Secret as the server after handshake success.
    """
    material = f"{username}|{client_nonce}|{server_nonce}".encode("utf-8")
    return hmac.new(
        SHARED_KEY.encode("utf-8"),
        material,
        hashlib.sha256
    ).hexdigest()


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    username = "olamide"
    password = "pass123"

    print(send_request(s, {
        "type": "register",
        "username": username,
        "password": password
    }))

    print(send_request(s, {
        "type": "login",
        "username": username,
        "password": password
    }))

    # Start the handshake with a fresh client nonce.
    client_nonce = secrets.token_hex(16)
    auth_start_response = send_request(s, {
        "type": "auth_start",
        "client_nonce": client_nonce
    })
    print(auth_start_response)

    if auth_start_response.get("status") != "ok":
        raise SystemExit("Handshake failed at auth_start.")

    server_nonce = auth_start_response["server_nonce"]
    server_proof = auth_start_response["server_proof"]

    if not verify_server_proof(username, client_nonce, server_nonce, server_proof):
        raise SystemExit("Server proof verification failed.")

    client_proof = create_client_proof(username, client_nonce, server_nonce)
    auth_finish_response = send_request(s, {
        "type": "auth_finish",
        "client_proof": client_proof
    })
    print(auth_finish_response)

    if auth_finish_response.get("status") != "ok":
        raise SystemExit("Handshake failed at auth_finish.")

    # Both sides now derive the same session keys from the same Master Secret.
    master_secret = derive_master_secret(username, client_nonce, server_nonce)
    kdf = KeyDerivation(master_secret)
    enc_key = kdf.derive_encryption_key()
    mac_key = kdf.derive_mac_key()
    secure_channel = SecureChannel(enc_key, mac_key)

    # Secure deposit request
    secure_request = secure_channel.wrap_secure_message({
        "action": "deposit",
        "amount": 500
    }, seq=1)

    secure_response = send_request(s, secure_request)
    print("Raw secure deposit response:", secure_response)
    print("Decrypted deposit response:", secure_channel.unwrap_secure_message(secure_response))

    # Secure balance request
    secure_request = secure_channel.wrap_secure_message({
        "action": "balance"
    }, seq=2)

    secure_response = send_request(s, secure_request)
    print("Raw secure balance response:", secure_response)
    print("Decrypted balance response:", secure_channel.unwrap_secure_message(secure_response))

    # Secure withdraw request
    secure_request = secure_channel.wrap_secure_message({
        "action": "withdraw",
        "amount": 200
    }, seq=3)

    secure_response = send_request(s, secure_request)
    print("Raw secure withdraw response:", secure_response)
    print("Decrypted withdraw response:", secure_channel.unwrap_secure_message(secure_response))

    # Secure balance request again
    secure_request = secure_channel.wrap_secure_message({
        "action": "balance"
    }, seq=4)

    secure_response = send_request(s, secure_request)
    print("Raw secure balance response:", secure_response)
    print("Decrypted balance response:", secure_channel.unwrap_secure_message(secure_response))