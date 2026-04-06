import socket
import threading
import hashlib

from storage import AccountStorage
from bank_logic import BankLogic
from client_session import ClientSession
from audit_logger import AuditLogger


HOST = "0.0.0.0"
PORT = 5000
ACCOUNTS_FILE = "data/accounts.json"
AUDIT_LOG_FILE = "data/audit.log"


def build_audit_log_key() -> bytes:
    """
    Create a stable AES key for encrypting audit logs.

    We derive it from a fixed server-side secret.
    
    """
    secret = "secure_audit_log_key_2026"
    return hashlib.sha256(secret.encode("utf-8")).digest()


def handle_client(client_socket: socket.socket, client_address, bank_logic: BankLogic, audit_logger: AuditLogger) -> None:
    session = ClientSession(client_socket, client_address, bank_logic, audit_logger)
    session.run()


def start_server() -> None:
    storage = AccountStorage(ACCOUNTS_FILE)
    bank_logic = BankLogic(storage)

    audit_key = build_audit_log_key()
    audit_logger = AuditLogger(AUDIT_LOG_FILE, audit_key)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    print(f"[SERVER] Listening on {HOST}:{PORT}")

    try:
        while True:
            client_socket, client_address = server_socket.accept()

            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address, bank_logic, audit_logger),
                daemon=True
            )
            client_thread.start()

    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")

    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server()