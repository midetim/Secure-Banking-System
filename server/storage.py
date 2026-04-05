import json
import os
import threading
import hashlib
from typing import Dict, Any


class AccountStorage:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.lock = threading.Lock()

        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)

        if not os.path.exists(self.filepath):
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump({}, f, indent=2)

    def _load_accounts(self) -> Dict[str, Any]:
        with open(self.filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_accounts(self, accounts: Dict[str, Any]) -> None:
        with open(self.filepath, "w", encoding="utf-8") as f:
            json.dump(accounts, f, indent=2)

    @staticmethod
    def hash_password(password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def register_user(self, username: str, password: str) -> tuple[bool, str]:
        with self.lock:
            accounts = self._load_accounts()

            if username in accounts:
                return False, "Username already exists."

            accounts[username] = {
                "password_hash": self.hash_password(password),
                "balance": 0.0
            }

            self._save_accounts(accounts)
            return True, "Registration successful."

    def authenticate_user(self, username: str, password: str) -> tuple[bool, str]:
        with self.lock:
            accounts = self._load_accounts()

            if username not in accounts:
                return False, "User does not exist."

            stored_hash = accounts[username]["password_hash"]
            if stored_hash != self.hash_password(password):
                return False, "Invalid password."

            return True, "Login successful."

    def get_balance(self, username: str) -> tuple[bool, str, float | None]:
        with self.lock:
            accounts = self._load_accounts()

            if username not in accounts:
                return False, "User does not exist.", None

            return True, "Balance retrieved.", accounts[username]["balance"]

    def deposit(self, username: str, amount: float) -> tuple[bool, str, float | None]:
        if amount <= 0:
            return False, "Deposit amount must be greater than 0.", None

        with self.lock:
            accounts = self._load_accounts()

            if username not in accounts:
                return False, "User does not exist.", None

            accounts[username]["balance"] += amount
            new_balance = accounts[username]["balance"]
            self._save_accounts(accounts)

            return True, "Deposit successful.", new_balance

    def withdraw(self, username: str, amount: float) -> tuple[bool, str, float | None]:
        if amount <= 0:
            return False, "Withdrawal amount must be greater than 0.", None

        with self.lock:
            accounts = self._load_accounts()

            if username not in accounts:
                return False, "User does not exist.", None

            current_balance = accounts[username]["balance"]
            if amount > current_balance:
                return False, "Insufficient funds.", current_balance

            accounts[username]["balance"] -= amount
            new_balance = accounts[username]["balance"]
            self._save_accounts(accounts)

            return True, "Withdrawal successful.", new_balance