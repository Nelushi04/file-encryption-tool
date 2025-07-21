import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import subprocess

# AES Configuration
BLOCK_SIZE = 16
KEY_LENGTH = 32
SALT_SIZE = 16

def pad(data):
    padding = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding]) * padding

def unpad(data):
    padding = data[-1]
    return data[:-padding]

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_LENGTH)

def encrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        salt = get_random_bytes(SALT_SIZE)
        key = derive_key(password.encode(), salt)
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data))
        encrypted_data = salt + cipher.iv + ct_bytes

        enc_file_path = file_path + ".enc"
        with open(enc_file_path, 'wb') as f:
            f.write(encrypted_data)

        return enc_file_path
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")
        return None

def decrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        salt = encrypted_data[:SALT_SIZE]
        iv = encrypted_data[SALT_SIZE:SALT_SIZE + BLOCK_SIZE]
        ct = encrypted_data[SALT_SIZE + BLOCK_SIZE:]

        key = derive_key(password.encode(), salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct))

        dec_file_path = file_path.replace('.enc', '')
        with open(dec_file_path, 'wb') as f:
            f.write(pt)

        return dec_file_path
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")
        return None

def open_file_location(filepath):
    folder = os.path.dirname(filepath)
    subprocess.run(["xdg-open", folder])

def encrypt_action():
    file_path = filedialog.askopenfilename(title="Select File to Encrypt")
    if file_path:
        password = password_entry.get()
        if not password:
            messagebox.showwarning("Missing Password", "Please enter a password.")
            return
        enc_path = encrypt_file(file_path, password)
        if enc_path:
            messagebox.showinfo("Success", "File encrypted successfully!")
            if messagebox.askyesno("Open Folder", "Do you want to view the encrypted file?"):
                open_file_location(enc_path)

def decrypt_action():
    file_path = filedialog.askopenfilename(title="Select File to Decrypt", filetypes=[("Encrypted Files", "*.enc")])
    if file_path:
        password = password_entry.get()
        if not password:
            messagebox.showwarning("Missing Password", "Please enter a password.")
            return
        dec_path = decrypt_file(file_path, password)
        if dec_path:
            messagebox.showinfo("Success", "File decrypted successfully!")
            if messagebox.askyesno("Open File", "Do you want to open the decrypted file?"):
                subprocess.run(["xdg-open", dec_path])

# ------------------- GUI Setup -------------------
root = tk.Tk()
root.title("AES File Encryptor & Decryptor")
root.geometry("500x300")
root.configure(bg="#f0f0f0")
root.resizable(False, False)

title_label = tk.Label(
    root,
    text="File Encryption & Decryption Tool",
    font=("Segoe UI", 15, "bold"),
    bg="#f0f0f0",
    fg="#333"
)
title_label.pack(pady=(20, 10))

tk.Label(
    root,
    text="Enter Password:",
    font=("Segoe UI", 11),
    bg="#f0f0f0"
).pack()

password_entry = tk.Entry(
    root,
    width=35,
    show="*",
    font=("Segoe UI", 10),
    relief="flat",
    bg="#ffffff",
    fg="#000000"
)
password_entry.pack(pady=10)

btn_encrypt = tk.Button(
    root,
    text="🔓 Encrypt File",
    width=25,
    font=("Segoe UI", 11),
    bg="#4CAF50",
    fg="white",
    activebackground="#45a049",
    relief="flat",
    command=encrypt_action
)
btn_encrypt.pack(pady=10)

btn_decrypt = tk.Button(
    root,
    text="🔓 Decrypt File",
    width=25,
    font=("Segoe UI", 11),
    bg="#2196F3",
    fg="white",
    activebackground="#1976D2",
    relief="flat",
    command=decrypt_action
)
btn_decrypt.pack()

root.mainloop()