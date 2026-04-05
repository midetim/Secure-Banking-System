import tkinter as tk
from tkinter import ttk, messagebox
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from secure_client import SecureClient

# ── Palette ──────────────────────────────────────────────────────────────────
BG        = "#0d1117"
PANEL     = "#161b22"
BORDER    = "#30363d"
ACCENT    = "#238636"
ACCENT_HV = "#2ea043"
RED       = "#da3633"
PURPLE    = "#6e40c9"
TEXT      = "#e6edf3"
MUTED     = "#8b949e"
MONO      = ("Courier New", 10)
SANS      = ("Segoe UI", 11)
SANS_SM   = ("Segoe UI", 10)
SANS_LG   = ("Segoe UI", 14, "bold")
SANS_XL   = ("Segoe UI", 20, "bold")


def styled_button(parent, text, color, command, width=14):
    btn = tk.Button(
        parent, text=text, bg=color, fg=TEXT,
        font=("Segoe UI", 11, "bold"), relief="flat",
        activebackground=color, activeforeground=TEXT,
        cursor="hand2", width=width, pady=6,
        command=command
    )
    return btn


def styled_entry(parent, show=None, width=30):
    e = tk.Entry(
        parent, font=SANS, bg=PANEL, fg=TEXT,
        insertbackground=TEXT, relief="flat",
        highlightthickness=1, highlightbackground=BORDER,
        highlightcolor=ACCENT, show=show, width=width
    )
    return e


class BankingApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure ATM — COE817")
        self.geometry("520x560")
        self.resizable(False, False)
        self.configure(bg=BG)
        self.client = SecureClient()
        self._show_login()

    def _clear(self):
        for w in self.winfo_children():
            w.destroy()

    # ── Login Screen ─────────────────────────────────────────────────────────

    def _show_login(self):
        self._clear()

        outer = tk.Frame(self, bg=BG)
        outer.pack(expand=True)

        # Header
        tk.Label(outer, text="🏦", font=("Segoe UI", 36), bg=BG, fg=TEXT).pack(pady=(0, 4))
        tk.Label(outer, text="Secure ATM", font=SANS_XL, bg=BG, fg=TEXT).pack()
        tk.Label(outer, text="COE817 — Banking Security Project",
                 font=SANS_SM, bg=BG, fg=MUTED).pack(pady=(2, 24))

        # Card
        card = tk.Frame(outer, bg=PANEL, padx=32, pady=28,
                        highlightthickness=1, highlightbackground=BORDER)
        card.pack(ipadx=10)

        tk.Label(card, text="Username", font=SANS_SM, bg=PANEL, fg=MUTED).pack(anchor="w")
        self.usr_entry = styled_entry(card)
        self.usr_entry.pack(fill="x", pady=(4, 14), ipady=6)

        tk.Label(card, text="Password", font=SANS_SM, bg=PANEL, fg=MUTED).pack(anchor="w")
        self.pwd_entry = styled_entry(card, show="•")
        self.pwd_entry.pack(fill="x", pady=(4, 20), ipady=6)

        btn_row = tk.Frame(card, bg=PANEL)
        btn_row.pack(fill="x")
        styled_button(btn_row, "Login", ACCENT, self._on_login).pack(side="left", padx=(0, 8))
        styled_button(btn_row, "Register", PURPLE, self._on_register).pack(side="left")

        self.status_var = tk.StringVar()
        self.status_lbl = tk.Label(card, textvariable=self.status_var,
                                   font=SANS_SM, bg=PANEL, fg=RED, wraplength=340)
        self.status_lbl.pack(pady=(14, 0))

        # Bind Enter key
        self.bind("<Return>", lambda e: self._on_login())
        self.usr_entry.focus()

    def _on_login(self):
        username = self.usr_entry.get().strip()
        password = self.pwd_entry.get()
        if not username or not password:
            self.status_var.set("Please enter username and password.")
            return
        try:
            self.client.connect()
            result = self.client.login(username, password)
            if result.get("status") != "ok":
                self.status_var.set(result.get("message", "Login failed."))
                self.client.disconnect()
                return
            if not self.client.handshake():
                self.status_var.set("Handshake failed — server authentication error.")
                self.client.disconnect()
                return
            self._show_dashboard(username)
        except ConnectionRefusedError:
            self.status_var.set("Cannot connect — is the server running?")
        except Exception as e:
            self.status_var.set(f"Error: {e}")
            self.client.disconnect()

    def _on_register(self):
        username = self.usr_entry.get().strip()
        password = self.pwd_entry.get()
        if not username or not password:
            self.status_var.set("Please enter username and password.")
            return
        try:
            self.client.connect()
            result = self.client.register(username, password)
            if result.get("status") == "ok":
                # Auto-login after successful registration
                login_result = self.client.login(username, password)
                if login_result.get("status") == "ok" and self.client.handshake():
                    self._show_dashboard(username)
                    return
            self.client.disconnect()
            msg = result.get("message", "Registration failed.")
            self.status_var.set(msg)
            self.status_lbl.config(fg=ACCENT if result.get("status") == "ok" else RED)
        except ConnectionRefusedError:
            self.status_var.set("Cannot connect — is the server running?")
        except Exception as e:
            self.status_var.set(f"Error: {e}")
            self.client.disconnect()

    # ── Dashboard ────────────────────────────────────────────────────────────

    def _show_dashboard(self, username: str):
        self._clear()
        self.unbind("<Return>")

        # Top bar
        topbar = tk.Frame(self, bg=PANEL, pady=12,
                          highlightthickness=1, highlightbackground=BORDER)
        topbar.pack(fill="x")
        tk.Label(topbar, text=f"🏦  Secure ATM  —  {username}",
                 font=SANS_LG, bg=PANEL, fg=TEXT).pack(side="left", padx=20)
        tk.Button(topbar, text="Logout", font=SANS_SM, bg=BG, fg=MUTED,
                  relief="flat", cursor="hand2", activebackground=BG,
                  command=self._on_logout).pack(side="right", padx=20)

        body = tk.Frame(self, bg=BG, padx=28, pady=20)
        body.pack(fill="both", expand=True)

        # Amount row
        amt_frame = tk.Frame(body, bg=BG)
        amt_frame.pack(fill="x", pady=(0, 16))
        tk.Label(amt_frame, text="Amount  $", font=SANS, bg=BG, fg=MUTED).pack(side="left")
        self.amt_entry = styled_entry(amt_frame, width=16)
        self.amt_entry.pack(side="left", padx=(6, 0), ipady=5)
        self.amt_entry.focus()

        # Action buttons
        btn_frame = tk.Frame(body, bg=BG)
        btn_frame.pack(fill="x", pady=(0, 20))
        styled_button(btn_frame, "⬆  Deposit",  ACCENT,  self._on_deposit,  width=13).pack(side="left", padx=(0, 8))
        styled_button(btn_frame, "⬇  Withdraw", RED,     self._on_withdraw, width=13).pack(side="left", padx=(0, 8))
        styled_button(btn_frame, "◎  Balance",  PURPLE,  self._on_balance,  width=13).pack(side="left")

        # Transaction log
        tk.Label(body, text="Transaction Log", font=SANS_SM,
                 bg=BG, fg=MUTED).pack(anchor="w", pady=(0, 6))

        log_card = tk.Frame(body, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        log_card.pack(fill="both", expand=True)

        self.log_box = tk.Text(
            log_card, font=MONO, bg=PANEL, fg=TEXT,
            relief="flat", bd=10, state="disabled",
            selectbackground=BORDER, height=12
        )
        self.log_box.pack(side="left", fill="both", expand=True)

        sb = ttk.Scrollbar(log_card, command=self.log_box.yview)
        sb.pack(side="right", fill="y")
        self.log_box.config(yscrollcommand=sb.set)

        # Tag colours for log entries
        self.log_box.tag_config("ok",    foreground="#3fb950")
        self.log_box.tag_config("error", foreground=RED)
        self.log_box.tag_config("info",  foreground=MUTED)

        self._log(f"Session started for {username}  ({datetime.now().strftime('%H:%M:%S')})", "info")

    def _on_deposit(self):
        amount = self._parse_amount()
        if amount is None:
            return
        try:
            result = self.client.deposit(amount)
            tag = "ok" if result.get("status") == "ok" else "error"
            bal = f"  |  Balance: ${result.get('balance', '?'):.2f}" if "balance" in result else ""
            self._log(f"DEPOSIT   ${amount:.2f}{bal}  —  {result.get('message', '')}", tag)
        except Exception as e:
            self._log(f"DEPOSIT   ERROR: {e}", "error")

    def _on_withdraw(self):
        amount = self._parse_amount()
        if amount is None:
            return
        try:
            result = self.client.withdraw(amount)
            tag = "ok" if result.get("status") == "ok" else "error"
            bal = f"  |  Balance: ${result.get('balance', '?'):.2f}" if "balance" in result else ""
            self._log(f"WITHDRAW  ${amount:.2f}{bal}  —  {result.get('message', '')}", tag)
        except Exception as e:
            self._log(f"WITHDRAW  ERROR: {e}", "error")

    def _on_balance(self):
        try:
            result = self.client.balance()
            tag = "ok" if result.get("status") == "ok" else "error"
            bal = f"${result.get('balance', '?'):.2f}" if "balance" in result else str(result)
            self._log(f"BALANCE   {bal}", tag)
        except Exception as e:
            self._log(f"BALANCE   ERROR: {e}", "error")

    def _on_logout(self):
        self.client.disconnect()
        self.client = SecureClient()
        self._show_login()

    def _parse_amount(self):
        try:
            val = float(self.amt_entry.get().strip())
            if val <= 0:
                raise ValueError
            return val
        except ValueError:
            messagebox.showerror("Invalid Amount", "Enter a positive number.")
            return None

    def _log(self, message: str, tag: str = "ok"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_box.config(state="normal")
        self.log_box.insert("end", f"[{ts}]  {message}\n", tag)
        self.log_box.see("end")
        self.log_box.config(state="disabled")


if __name__ == "__main__":
    app = BankingApp()
    app.mainloop()
