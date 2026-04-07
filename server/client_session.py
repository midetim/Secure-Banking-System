import json
import socket

from bank_logic import BankLogic
from auth_protocol import AuthProtocol
from key_derivation import KeyDerivation
from secure_channel import SecureChannel


class ClientSession:
    def __init__(self, client_socket: socket.socket, client_address, bank_logic: BankLogic, audit_logger, event_callback=None):
        self.client_socket = client_socket
        self.client_address = client_address
        self.bank_logic = bank_logic
        self.audit_logger = audit_logger
        self.event_callback = event_callback
        self.buffer_size = 4096

        self.logged_in_user = None
        self.handshake_complete = False
        self.client_nonce = None
        self.server_nonce = None
        self.master_secret = None

        self.enc_key = None
        self.mac_key = None
        self.secure_channel = None

        self.auth = AuthProtocol(shared_key="bank_shared_secret_2026")

    def _emit(self, event_type: str, **kwargs) -> None:
        if self.event_callback:
            self.event_callback(event_type, {"addr": self.client_address, **kwargs})

    def send_json(self, data: dict) -> None:
        message = json.dumps(data) + "\n"
        self.client_socket.sendall(message.encode("utf-8"))

    def receive_json(self) -> dict | None:
        data = b""

        while b"\n" not in data:
            chunk = self.client_socket.recv(self.buffer_size)
            if not chunk:
                return None
            data += chunk

        raw_message = data.decode("utf-8").strip()

        try:
            return json.loads(raw_message)
        except json.JSONDecodeError:
            return None

    def _reset_handshake_state(self) -> None:
        """
        Clear all authentication and secure session state.
        """
        self.handshake_complete = False
        self.client_nonce = None
        self.server_nonce = None
        self.master_secret = None
        self.enc_key = None
        self.mac_key = None
        self.secure_channel = None

    def _handle_auth_start(self, request: dict) -> dict:
        """
        Handle the first handshake step from the client.
        """
        if self.logged_in_user is None:
            return {"status": "error", "message": "You must log in before starting authentication."}

        client_nonce = request.get("client_nonce")
        if not client_nonce:
            return {"status": "error", "message": "Missing client nonce."}

        self.client_nonce = client_nonce
        self.server_nonce = self.auth.generate_nonce()

        server_proof = self.auth.create_server_proof(
            username=self.logged_in_user,
            client_nonce=self.client_nonce,
            server_nonce=self.server_nonce
        )

        return {
            "status": "ok",
            "type": "auth_challenge",
            "server_nonce": self.server_nonce,
            "server_proof": server_proof,
            "message": "Server challenge created."
        }

    def _handle_auth_finish(self, request: dict) -> dict:
        """
        Handle the final handshake step from the client.
        """
        if self.logged_in_user is None:
            return {"status": "error", "message": "You must log in first."}

        if self.client_nonce is None or self.server_nonce is None:
            return {"status": "error", "message": "Handshake was not started properly."}

        client_proof = request.get("client_proof")
        if not client_proof:
            return {"status": "error", "message": "Missing client proof."}

        valid = self.auth.verify_client_proof(
            username=self.logged_in_user,
            client_nonce=self.client_nonce,
            server_nonce=self.server_nonce,
            proof=client_proof
        )

        if not valid:
            self._reset_handshake_state()
            self._emit("auth_fail")
            return {"status": "error", "message": "Client authentication failed."}

        self.master_secret = self.auth.derive_master_secret(
            username=self.logged_in_user,
            client_nonce=self.client_nonce,
            server_nonce=self.server_nonce
        )

        kdf = KeyDerivation(self.master_secret)
        self.enc_key = kdf.derive_encryption_key()
        self.mac_key = kdf.derive_mac_key()

        self.secure_channel = SecureChannel(self.enc_key, self.mac_key)
        self.handshake_complete = True

        self._emit("auth_success", username=self.logged_in_user)

        return {
            "status": "ok",
            "type": "auth_success",
            "message": "Mutual authentication successful. Session keys established."
        }

    def _handle_secure_request(self, request: dict) -> dict:
        """
        Verify and decrypt a secure request, process the banking action,
        then return a secure response.
        """
        if not self.handshake_complete or self.secure_channel is None:
            return {"status": "error", "message": "Secure authentication must be completed first."}

        try:
            inner_payload = self.secure_channel.unwrap_secure_message(request)
        except Exception as e:
            return {"status": "error", "message": f"Secure message rejected: {str(e)}"}

        action = inner_payload.get("action")
        seq = request.get("seq")

        if action == "balance":
            response_payload = self.bank_logic.balance(self.logged_in_user)

            # Log the balance inquiry so the audit file reflects user activity.
            self.audit_logger.log_action(self.logged_in_user, "balance inquiry")
            self._emit("transaction", username=self.logged_in_user, action="balance inquiry")

        elif action == "deposit":
            try:
                amount = float(inner_payload.get("amount", 0))
            except (TypeError, ValueError):
                response_payload = {"status": "error", "message": "Invalid deposit amount."}
            else:
                response_payload = self.bank_logic.deposit(self.logged_in_user, amount)

                if response_payload["status"] == "ok":
                    self.audit_logger.log_action(
                        self.logged_in_user,
                        f"deposit {amount}"
                    )
                    self._emit("transaction", username=self.logged_in_user, action=f"deposit ${amount:.2f}")

        elif action == "withdraw":
            try:
                amount = float(inner_payload.get("amount", 0))
            except (TypeError, ValueError):
                response_payload = {"status": "error", "message": "Invalid withdrawal amount."}
            else:
                response_payload = self.bank_logic.withdraw(self.logged_in_user, amount)

                if response_payload["status"] == "ok":
                    self.audit_logger.log_action(
                        self.logged_in_user,
                        f"withdraw {amount}"
                    )
                    self._emit("transaction", username=self.logged_in_user, action=f"withdraw ${amount:.2f}")

        else:
            response_payload = {"status": "error", "message": "Unknown secure action."}

        return self.secure_channel.wrap_secure_message(response_payload, seq)

    def handle_request(self, request: dict) -> dict:
        request_type = request.get("type")

        if request_type == "register":
            username = request.get("username", "").strip()
            password = request.get("password", "")
            return self.bank_logic.register(username, password)

        if request_type == "login":
            username = request.get("username", "").strip()
            password = request.get("password", "")
            result = self.bank_logic.login(username, password)

            if result["status"] == "ok":
                self.logged_in_user = username
                self._reset_handshake_state()
                self._emit("login", username=username)

            return result

        if request_type == "auth_start":
            return self._handle_auth_start(request)

        if request_type == "auth_finish":
            return self._handle_auth_finish(request)

        if request_type == "logout":
            self.logged_in_user = None
            self._reset_handshake_state()
            return {"status": "ok", "message": "Logged out successfully."}

        if self.logged_in_user is None:
            return {"status": "error", "message": "You must log in first."}

        if request_type == "secure":
            return self._handle_secure_request(request)

        return {"status": "error", "message": "Unknown request type."}

    def run(self) -> None:
        print(f"[+] Client connected: {self.client_address}")
        self._emit("connect")

        try:
            while True:
                request = self.receive_json()

                if request is None:
                    print(f"[-] Client disconnected or sent invalid JSON: {self.client_address}")
                    break

                response = self.handle_request(request)
                self.send_json(response)

        except Exception as e:
            print(f"[!] Error in session {self.client_address}: {e}")
            self._emit("error", msg=str(e))

        finally:
            self.client_socket.close()
            print(f"[x] Connection closed: {self.client_address}")
            self._emit("disconnect", username=self.logged_in_user)