import os
import tkinter as tk
from tkinter import messagebox, ttk
from secure_vault import SecureVault
from secure_clipboard import SecureClipboard
from password_generator import generate_password

VAULTS_DIR = "vaults"
AUTOLOCK_TIMEOUT = 5 * 60 * 1000  # 5 minutes in milliseconds

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Vault")
        self.root.geometry("420x450")
        self.root.resizable(False, False)

        os.makedirs(VAULTS_DIR, exist_ok=True)

        self.vault = None
        self.clipboard = SecureClipboard(root, clear_after=15)
        self.autolock_job = None

        self.main_frame = tk.Frame(root)
        self.main_frame.pack(expand=True, fill="both")

        self.root.protocol("WM_DELETE_WINDOW", self.on_exit)

        # Bind any keypress or mouse click to reset autolock
        self.root.bind_all("<Any-KeyPress>", self.reset_autolock)
        self.root.bind_all("<Any-Button>", self.reset_autolock)

        self.show_login()

    # ---------- Helpers ----------
    def clear(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    # ---------- Login / Vault Unlock ----------
    def show_login(self):
        self.clear()
        self.cancel_autolock()

        tk.Label(self.main_frame, text="Secure Vault", font=("Arial", 16)).pack(pady=10)

        tk.Label(self.main_frame, text="Vault Name").pack()
        self.vault_entry = tk.Entry(self.main_frame)
        self.vault_entry.pack()

        tk.Label(self.main_frame, text="Master Password").pack(pady=(10, 0))
        self.master_entry = tk.Entry(self.main_frame, show="*")
        self.master_entry.pack()

        tk.Button(
            self.main_frame,
            text="Unlock / Create Vault",
            command=self.unlock_or_create
        ).pack(pady=15)

    def unlock_or_create(self):
        name = self.vault_entry.get().strip()
        password = self.master_entry.get()

        if not name or not password:
            messagebox.showerror("Error", "Vault name and password required")
            return

        vault_path = os.path.join(VAULTS_DIR, name)
        self.vault = SecureVault(vault_path)

        try:
            if os.path.exists(self.vault.data_file):
                # Existing vault → unlock
                self.vault.unlock(password)
            else:
                # First-run → create new vault
                self.vault.create(password)
        except Exception as e:
            messagebox.showerror("Error", f"Cannot access vault: {str(e)}")
            return

        self.show_main_ui()

    # ---------- Main UI ----------
    def show_main_ui(self):
        self.clear()
        self.start_autolock_timer()

        tk.Label(self.main_frame, text="Password Manager", font=("Arial", 14)).pack(pady=10)

        tk.Label(self.main_frame, text="Site").pack()
        self.site_entry = tk.Entry(self.main_frame)
        self.site_entry.pack()

        tk.Label(self.main_frame, text="Username").pack()
        self.user_entry = tk.Entry(self.main_frame)
        self.user_entry.pack()

        tk.Label(self.main_frame, text="Password").pack()
        self.pass_entry = tk.Entry(self.main_frame, show="*")
        self.pass_entry.pack()

        # ---------- Buttons ----------
        tk.Button(self.main_frame, text="Generate Password", command=self.generate_password_ui).pack(pady=5)
        tk.Button(self.main_frame, text="Save Entry", command=self.save_entry).pack(pady=5)
        tk.Button(self.main_frame, text="Load Saved Passwords", command=self.open_load_window).pack(pady=5)
        tk.Button(self.main_frame, text="Copy Password", command=self.copy_password).pack(pady=5)

        self.status_label = tk.Label(self.main_frame, text="", fg="green")
        self.status_label.pack(pady=10)

        tk.Button(self.main_frame, text="Lock Vault", command=self.lock_vault).pack(pady=10)

    # ---------- Actions ----------
    def generate_password_ui(self):
        self.pass_entry.config(show="*")
        password = generate_password(length=20)
        self.pass_entry.delete(0, tk.END)
        self.pass_entry.insert(0, password)
        self.clipboard.copy(password)
        self.status_label.config(text="Password generated & copied (15s)")

    def save_entry(self):
        site = self.site_entry.get().strip()
        user = self.user_entry.get().strip()
        password = self.pass_entry.get().strip()

        if not site or not user or not password:
            messagebox.showerror("Error", "All fields required")
            return

        self.vault.add_entry(site, user, password)
        self.pass_entry.config(show="*")
        self.status_label.config(text=f"Saved entry for {site}")

    # ---------- Load Window ----------
    def open_load_window(self):
        if not self.vault.data["entries"]:
            messagebox.showinfo("Empty", "No saved entries")
            return

        win = tk.Toplevel(self.root)
        win.title("Load Password")
        win.geometry("320x180")
        win.resizable(False, False)

        tk.Label(win, text="Select Site").pack(pady=10)

        sites = sorted(self.vault.data["entries"].keys())
        site_var = tk.StringVar(value=sites[0])

        dropdown = ttk.Combobox(win, textvariable=site_var, values=sites, state="readonly")
        dropdown.pack(fill="x", padx=20)

        def load_selected():
            site = site_var.get()
            entry = self.vault.get_entry(site)
            if not entry:
                return

            self.site_entry.delete(0, tk.END)
            self.site_entry.insert(0, site)

            self.user_entry.delete(0, tk.END)
            self.user_entry.insert(0, entry["username"])

            self.pass_entry.config(show="")
            self.pass_entry.delete(0, tk.END)
            self.pass_entry.insert(0, entry["password"])

            self.clipboard.copy(entry["password"])
            self.status_label.config(text=f"Loaded entry for {site} (copied to clipboard)")

            win.destroy()

        tk.Button(win, text="Load", command=load_selected).pack(pady=15)

    # ---------- Clipboard ----------
    def copy_password(self):
        password = self.pass_entry.get()
        if password:
            self.clipboard.copy(password)
            self.status_label.config(text="Password copied (15s)")

    # ---------- Lock Vault ----------
    def lock_vault(self):
        self.clipboard.clear()
        if self.vault:
            self.vault.lock()
            self.vault = None
        self.cancel_autolock()
        self.show_login()

    # ---------- Auto-Lock ----------
    def start_autolock_timer(self):
        self.cancel_autolock()
        self.autolock_job = self.root.after(AUTOLOCK_TIMEOUT, self.auto_lock)

    def reset_autolock(self, event=None):
        if self.vault and self.vault.is_unlocked:
            self.start_autolock_timer()

    def cancel_autolock(self):
        if self.autolock_job is not None:
            self.root.after_cancel(self.autolock_job)
            self.autolock_job = None

    def auto_lock(self):
        if self.vault:
            self.vault.lock()
            self.vault = None
        self.clipboard.clear()
        messagebox.showinfo("Auto-Lock", "Vault locked due to inactivity")
        self.show_login()

    # ---------- Exit ----------
    def on_exit(self):
        try:
            self.clipboard.shutdown()
        except Exception:
            pass
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
