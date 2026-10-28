import asyncio
import flet as ft

from cryptography.exceptions import InvalidTag
from crypto_core import encrypt_bytes, decrypt_bytes

ENCRYPTED_EXTENSION = ".enc"

def format_size(num_bytes: int) -> str:
    size = float(num_bytes or 0)
    for unit in ("B","KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024

def main(page: ft.Page):
    page.title = "File Encryption Tool"
    page.padding = 20
    page.window.width = 480
    page.window.height = 420

    file_picker = ft.FilePicker()
    page.services.append(file_picker)

    selected = {"name": None, "data": None}

    # Controls
    file_label = ft.Text("No file selected", expand=True, overflow=ft.TextOverflow.ELLIPSIS)
    browse_button = ft.Button(content="Browse...", icon=ft.Icons.FOLDER_OPEN)
    password_field = ft.TextField(label="Password", password=True, can_reveal_password=True)
    encrypt_button = ft.Button(content="Encrypt", icon=ft.Icons.LOCK, expand=True)
    decrypt_button = ft.Button(content="Decrypt", icon=ft.Icons.LOCK, expand=True)
    progress = ft.ProgressRing(visible=False, width=20, height=20)
    status = ft.Text("", color=ft.Colors.GREY)

    # Helpers
    def set_status(message: str, color=ft.Colors.GREY):
        status.value = message
        status.color = color
        page.update()

    def set_busy(busy: bool, message: str = ""):
        for control in (browse_button, encrypt_button, decrypt_button, password_field):
            control.disabled = busy
        progress.visible = busy
        set_status(message)

    def is_mobile() -> bool:
        return page.platform in (ft.PagePlatform.ANDROID, ft.PagePlatform.IOS)

    # Actions
    async def browse(e):
        files = await file_picker.pick_files(dialog_title="Select a file", with_data=True)
        if not files:
            return
        picked = files[0]
        data = picked.bytes
        if data is None and picked.path:
            try:
                with open(picked.path, "rb") as f:
                    data = f.read()
            except OSError as ex:
                set_status(f"Could not read the file:{ex}", ft.Colors.RED)
                return
        if data is None:
            set_status("Could not read this file.", ft.Colors.RED)
            return

        selected["name"] = picked.name
        selected["data"] = data
        file_label.value = f"{picked.name} ({format_size(len(data))})"
        set_status("")

    async def run_operation(mode: str):
        password = password_field.value
        if selected["data"] is None:
            set_status("Please select a file first.", ft.Colors.RED)
            return
        if not password:
            set_status("Please enter a password.", ft.Colors.RED)
            return

        name = selected["name"]
        if mode == "encrypt":
            set_busy(True, "Encrypting...")
            worker = encrypt_bytes
            suggested_name = name + ENCRYPTED_EXTENSION
            done_verb = "Encrypted"
        else:
            set_busy(True, "Decrypting...")
            worker = decrypt_bytes
            suggested_name = (
                name[: -len(ENCRYPTED_EXTENSION)]
                if name.endswith(ENCRYPTED_EXTENSION)
                else name + ".dec"
            )
            done_verb = "Decrypted"
        
        try:
            result = await asyncio.to_thread(worker, selected["data"], password)
        except InvalidTag:
            set_busy(False)
            set_status("Incorrect password, or the file is corrupted/tampered with.", ft.Colors.RED)
            return
        except Exception as ex:
            set_busy(False)
            set_status(f"Unexpected error: {ex}", ft.Colors.RED)
            return
        
        set_busy(False, "Choose where to save the result...")
        try:
            saved = await file_picker.save_file(dialog_title=f"Save {done_verb.lower()} file", file_name=suggested_name, src_bytes=result)
        except Exception as ex:
            set_status(f"Could not save the file: {ex}", ft.Colors.RED)
            return
        
        if saved:
            set_status(f"{done_verb} and saved: {saved}", ft.Colors.GREEN)
        elif is_mobile():
            set_status(f"{done_verb}. check the location you picked.", ft.Colors.GREEN)
        else:
            set_status("Save cancelled - nothing was written.", ft.Colors.ORANGE)
        
    async def on_encrypt(e):
        await run_operation("encrypt")

    async def on_decrypt(e):
        await run_operation("decrypt")

    browse_button.on_click = browse
    encrypt_button.on_click = on_encrypt
    decrypt_button.on_click = on_decrypt

    # Layout
    page.add(
        ft.SafeArea(
            content=ft.Column(
                spacing=20,
                controls=[
                    ft.Text("File Encryption Tool", size=22, weight=ft.FontWeight.BOLD),
                    ft.Row(controls=[file_label, browse_button]),
                    password_field,
                    ft.Row(controls=[encrypt_button, decrypt_button]),
                    ft.Row(controls=[progress, status]),
                ],
            )
        )
    )