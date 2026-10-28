import asyncio
import os
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import flet as ft
import gui
from crypto_core import encrypt_bytes, decrypt_bytes

PASSWORD = "correct-horse-battery-staple"
ORIGINAL = b"Top secret contents \x00\x01\x02 with binary bytes."

# Test scaffolding
class FakePicker:
    def __init__(self):
        self.next_pick = []
        self.save_result = "/fake/saved/output"
        self.saved = None
        self.save_calls = 0

    async def pick_files(self, **kwargs):
        return self.next_pick

    async def save_file(self, **kwargs):
        self.save_calls += 1
        self.saved = kwargs
        return self.save_result

def walk(control):
    yield control
    content = getattr(control, "content", None)
    if content is not None and not isinstance(content, str):
        yield from walk(content)
    for child in getattr(control, "controls", None) or []:
        yield from walk(child)

class App:
    def __init__(self, platform=ft.PagePlatform.LINUX):
        self.picker = FakePicker()
        self.page = MagicMock()
        self.page.services = []
        self.page.platform = platform
        with patch.object(gui.ft, "FilePicker", lambda: self.picker):
            gui.main(self.page)

        root = self.page.add.call_args.args[0]
        controls = list(walk(root))
        buttons = {c.content: c for c in controls if isinstance(c, ft.Button)}
        texts = [c for c in controls if isinstance(c, ft.Text)]

        self.browse = buttons["Browse..."]
        self.encrypt = buttons["Encrypt"]
        self.decrypt = buttons["Decrypt"]
        self.password = next(c for c in controls if isinstance(c, ft.TextField))
        self.progress = next(c for c in controls if isinstance(c, ft.ProgressRing))
        self.file_label = texts[1]
        self.status = texts[-1]

    def pick(self, name, data=None, path=None):
        size = len(data) if data is not None else 0
        self.picker.next_pick = [SimpleNamespace(name=name, path=path, size=size, bytes=data)]
        asyncio.run(self.browse.on_click(None))

    def click(self, button):
        asyncio.run(button.on_click(None))

    def assert_idle(self):
        for c in (self.browse, self.encrypt, self.decrypt, self.password):
            assert not c.disabled, "a control was left disabled"
        assert not self.progress.visible, "progress ring left visible"

# Scenarios
def test_encrypt_happy_path():
    app = App()
    app.pick("secret.txt", ORIGINAL)
    assert "secret.txt" in app.file_label.value
    app.password.value = PASSWORD
    app.click(app.encrypt)

    saved = app.picker.saved
    assert saved["file_name"] == "secret.txt.enc", saved["file_name"]
    assert saved["src_bytes"] != ORIGINAL
    assert decrypt_bytes(saved["src_bytes"], PASSWORD) == ORIGINAL
    assert "Encrypted and saved" in app.status.value
    app.assert_idle()
    print("[ok] Encrypt: right filename, output decrypts to the original, UI re-enabled.")

def test_decrypt_happy_path():
    app = App()
    app.pick("secret.txt.enc", encrypt_bytes(ORIGINAL, PASSWORD))
    app.password.value = PASSWORD
    app.click(app.decrypt)

    saved = app.picker.saved
    assert saved["file_name"] == "secret.txt", saved["file_name"]
    assert saved["src_bytes"] == ORIGINAL
    assert "Decrypted and saved" in app.status.value
    app.assert_idle()
    print("[ok] Decrypt: .enc stripped from name, original bytes recovered.")

def test_decrypt_non_enc_name_gets_dec_suffix():
    app = App()
    app.pick("mystery.bin", encrypt_bytes(ORIGINAL, PASSWORD))
    app.password.value = PASSWORD
    app.click(app.decrypt)
    assert app.picker.saved["file_name"] == "mystery.bin.dec"
    print("[ok] Decrypting a file without .enc suggests a .dec name.")

def test_wrong_password_shows_message_and_saves_nothing():
    app = App()
    app.pick("secret.txt.enc", encrypt_bytes(ORIGINAL, PASSWORD))
    app.password.value = "wrong-password"
    app.click(app.decrypt)

    assert "Incorrect password" in app.status.value, app.status.value
    assert app.picker.save_calls == 0, "app tried to save after a failed decrypt"
    app.assert_idle()
    print("[ok] Wrong password: clear message, nothing saved, UI re-enabled.")

def test_corrupted_and_truncated_files_show_same_message():
    for label, data in [("empty file", b""), ("too short", b"abc"), ("garbage", os.urandom(200))]:
        app = App()
        app.pick("bad.enc", data)
        app.password.value = PASSWORD
        app.click(app.decrypt)
        assert "Incorrect password" in app.status.value, f"{label}: {app.status.value}"
        assert app.picker.save_calls == 0
    print("[ok] Empty/short/garbage files give the clean error, not a crash.")

def test_validation_messages():
    app = App()
    app.password.value = PASSWORD
    app.click(app.encrypt)
    assert "select a file" in app.status.value.lower()

    app.pick("a.txt", ORIGINAL)
    app.password.value = ""
    app.click(app.encrypt)
    assert "enter a password" in app.status.value.lower()
    assert app.picker.save_calls == 0
    print("[ok] Missing file / missing password are caught before any work.")

def test_cancelled_save_on_desktop():
    app = App(platform=ft.PagePlatform.LINUX)
    app.picker.save_result = None
    app.pick("a.txt", ORIGINAL)
    app.password.value = PASSWORD
    app.click(app.encrypt)
    assert "cancelled" in app.status.value.lower(), app.status.value
    print("[ok] Desktop: cancelling the save dialog is reported as cancelled.")

def test_android_save_result_not_guessed():
    app = App(platform=ft.PagePlatform.ANDROID)
    app.picker.save_result = None
    app.pick("a.txt", ORIGINAL)
    app.password.value = PASSWORD
    app.click(app.encrypt)
    assert "cancelled" not in app.status.value.lower(), app.status.value
    assert "Encrypted" in app.status.value
    print("[ok] Android: a None save result is not mislabelled as cancelled.")

def test_picker_without_bytes_falls_back_to_path():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(ORIGINAL)
    try:
        app = App()
        app.pick("onDisk.txt", data=None, path=tmp.name)
        app.password.value = PASSWORD
        app.click(app.encrypt)
        assert decrypt_bytes(app.picker.saved["src_bytes"], PASSWORD) == ORIGINAL
        print("[ok] If the picker gives a path but no bytes, the file is read from disk.")
    finally:
        os.remove(tmp.name)

def test_unreadable_file_is_reported():
    app = App()
    app.pick("ghost.txt", data=None, path=None)
    assert "could not read" in app.status.value.lower(), app.status.value
    app.pick("ghost2.txt", data=None, path="/definitely/not/a/real/path")
    assert "could not read" in app.status.value.lower(), app.status.value
    print("[ok] Unreadable files produce a clear message instead of a crash.")

def test_cancelled_pick_keeps_previous_selection():
    app = App()
    app.pick("first.txt", ORIGINAL)
    app.picker.next_pick = []                 # user opens the dialog and cancels
    asyncio.run(app.browse.on_click(None))
    assert "first.txt" in app.file_label.value
    print("[ok] Cancelling the file picker keeps the earlier selection.")

def main():
    test_encrypt_happy_path()
    test_decrypt_happy_path()
    test_decrypt_non_enc_name_gets_dec_suffix()
    test_wrong_password_shows_message_and_saves_nothing()
    test_corrupted_and_truncated_files_show_same_message()
    test_validation_messages()
    test_cancelled_save_on_desktop()
    test_android_save_result_not_guessed()
    test_picker_without_bytes_falls_back_to_path()
    test_unreadable_file_is_reported()
    test_cancelled_pick_keeps_previous_selection()
    print("\nAll GUI tests passed.")

if __name__ == "__main__":
    main()