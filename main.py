import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
from cryptography.fernet import Fernet

# Functions from the earlier steps remain the same
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("secret.key", "rb").read()

def encrypt_message(message):
    key = load_key()
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message):
    key = load_key()
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message.decode()

# Updated GUI Functions
def encrypt_message_gui():
    msg = txt_input.get("1.0", tk.END).strip()  # Get message from input text box
    if msg:
        encrypted_msg = encrypt_message(msg)
        txt_result.delete("1.0", tk.END)  # Clear previous result
        txt_result.insert("1.0", encrypted_msg)  # Show encrypted message
    else:
        messagebox.showwarning("Warning", "Please enter a message to encrypt.")

def decrypt_message_gui():
    msg = txt_input.get("1.0", tk.END).strip()  # Get message from input text box
    try:
        decrypted_msg = decrypt_message(bytes(msg, 'utf-8'))
        txt_result.delete("1.0", tk.END)  # Clear previous result
        txt_result.insert("1.0", decrypted_msg)  # Show decrypted message
    except Exception as e:
        messagebox.showerror("Error", "An error occurred during decryption. Ensure the input is an encrypted message.")

# Main GUI App
def main_app():
    global txt_input, txt_result
    root = tk.Tk()
    root.title("Encryption/Decryption Tool")
    root.geometry("500x300")

    tk.Label(root, text="Enter Text:").pack(pady=5)
    txt_input = scrolledtext.ScrolledText(root, height=5)
    txt_input.pack(pady=5)

    tk.Button(root, text="Encrypt Message", command=encrypt_message_gui).pack(pady=5)
    tk.Button(root, text="Decrypt Message", command=decrypt_message_gui).pack(pady=5)

    tk.Label(root, text="Result:").pack(pady=5)
    txt_result = scrolledtext.ScrolledText(root, height=5)
    txt_result.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    generate_key()  # Generate and save a key if it doesn't exist
    main_app()

