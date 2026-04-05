from storage import AccountStorage


class BankLogic:
    def __init__(self, storage: AccountStorage):
        self.storage = storage

    def register(self, username: str, password: str) -> dict:
        if not username or not password:
            return {"status": "error", "message": "Username and password are required."}

        success, message = self.storage.register_user(username, password)
        return {
            "status": "ok" if success else "error",
            "message": message
        }

    def login(self, username: str, password: str) -> dict:
        if not username or not password:
            return {"status": "error", "message": "Username and password are required."}

        success, message = self.storage.authenticate_user(username, password)
        return {
            "status": "ok" if success else "error",
            "message": message
        }

    def balance(self, username: str) -> dict:
        success, message, balance = self.storage.get_balance(username)
        return {
            "status": "ok" if success else "error",
            "message": message,
            "balance": balance
        }

    def deposit(self, username: str, amount: float) -> dict:
        success, message, balance = self.storage.deposit(username, amount)
        return {
            "status": "ok" if success else "error",
            "message": message,
            "balance": balance
        }

    def withdraw(self, username: str, amount: float) -> dict:
        success, message, balance = self.storage.withdraw(username, amount)
        return {
            "status": "ok" if success else "error",
            "message": message,
            "balance": balance
        }