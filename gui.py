import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

from cryptography.exceptions import InvalidTag
from crypto_core import encrypt_file, decrypt_file

ENCRYPTED_EXTENSION = ".enc"

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryption Tool")
        self.root.geometry("420x220")
        self.root.resizable(False, False)

        self.input_path = tk.StringVar()

        # File selection row
        tk.Label(root, text="File:").grid(row=0, column=0, padx=10, pady=15, sticky="w")
        tk.Entry(root, textvariable=self.input_path, width=35).grid(row=0, column=1, pady=15)
        tk.Button(root, text="Browse...", command=self.browse_file).grid(row=0, column=2, padx=10)

        #Password row
        tk.Label(root, text="Password:").grid(row=1, column=0, padx=10, sticky="w")
        self.password_entry = tk.Entry(root, show="*", width=35)
        self.password_entry.grid(row=1, column=1, columnspan=2, pady=5, sticky="w", padx=(0, 10))

        #Action buttons
        button_frame = tk.Frame(root)
        button_frame.grid(row=2, column=0, columnspan=3, pady=25)
        self.encrypt_button = tk.Button(button_frame, text="Encrypt", width=15, command=self.handle_encrypt)
        self.decrypt_button = tk.Button(button_frame, text="Decrypt", width=15, command=self.handle_decrypt)
        self.encrypt_button.pack(side="left", padx=10)
        self.decrypt_button.pack(side="left", padx=10)

        #Status label
        self.status_label = tk.Label(root, text="", fg="gray")
        self.status_label.grid(row=3, column=0, columnspan=3)

    #UI helpers
    def browse_file(self):
        path = filedialog.askopenfilename(title="Select a file")
        if path:
            self.input_path.set(path)
            self.status_label.config(text="")

    def validate_inputs(self):
        """Returns (input_path, password) if valid, or None (after showing an error)."""
        input_path = self.input_path.get().strip()
        password = self.password_entry.get()

        if not input_path:
            messagebox.showerror("Missing file", "Please select a file first.")
            return None
        if not os.path.isfile(input_path):
            messagebox.showerror("File not found", f"Could not find:\n{input_path}")
            return None
        if not password:
            messagebox.showerror("Missing password", "Please enter a password.")
            return None
        return input_path, password

    def confirm_overwrite(self, output_path):
        if os.path.exists(output_path):
            return messagebox.askyesno(
                "File already exists",
                f"{os.path.basename(output_path)} already exists. Overwrite it?",
            )
        return True

    def set_busy(self, busy: bool, message: str = ""):
        state = "disabled" if busy else "normal"
        self.encrypt_button.config(state=state)
        self.decrypt_button.config(state=state)
        self.status_label.config(text=message, fg="gray")
        self.root.update_idletasks()

    def run_in_background(self, target):
        """Run a slow operation off the main thread so the UI doesn't freeze."""
        thread = threading.Thread(target=target, daemon=True)
        thread.start()

    #Actions
    def handle_encrypt(self):
        validated = self.validate_inputs()
        if not validated:
            return
        input_path, password = validated
        output_path = input_path + ENCRYPTED_EXTENSION

        if not self.confirm_overwrite(output_path):
            return

        self.set_busy(True, "Encrypting...")

        def work():
            try:
                encrypt_file(input_path, output_path, password)
                self.root.after(0, self.on_success, "Encrypted", output_path)
            except PermissionError:
                self.root.after(0, self.on_error, "Permission denied while writing the output file.")
            except OSError as e:
                self.root.after(0, self.on_error, f"Could not read/write file:\n{e}")
            except Exception as e:
                self.root.after(0, self.on_error, f"Unexpected error:\n{e}")

        self.run_in_background(work)

    def handle_decrypt(self):
        validated = self.validate_inputs()
        if not validated:
            return
        input_path, password = validated

        if input_path.endswith(ENCRYPTED_EXTENSION):
            output_path = input_path[: -len(ENCRYPTED_EXTENSION)]
        else:
            output_path = input_path + ".dec"

        if not self.confirm_overwrite(output_path):
            return

        self.set_busy(True, "Decrypting...")

        def work():
            try:
                decrypt_file(input_path, output_path, password)
                self.root.after(0, self.on_success, "Decrypted", output_path)
            except InvalidTag:
                self.root.after(
                    0, self.on_error, "Incorrect password, or the file is corrupted/tampered with."
                )
            except PermissionError:
                self.root.after(0, self.on_error, "Permission denied while writing the output file.")
            except OSError as e:
                self.root.after(0, self.on_error, f"Could not read/write file:\n{e}")
            except Exception as e:
                self.root.after(0, self.on_error, f"Unexpected error:\n{e}")

        self.run_in_background(work)

    #Result callbacks
    def on_success(self, verb, output_path):
        self.set_busy(False, f"{verb} -> {os.path.basename(output_path)}")
        self.status_label.config(fg="green")
        messagebox.showinfo("Success", f"{verb}:\n{output_path}")

    def on_error(self, message):
        self.set_busy(False, "Failed.")
        self.status_label.config(fg="red")
        messagebox.showerror("Error", message)

def launch():
    root = tk.Tk()
    EncryptionApp(root)
    root.mainloop()