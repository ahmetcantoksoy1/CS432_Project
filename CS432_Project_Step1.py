import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, scrolledtext
import socket
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import hashlib, os

class SecureClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Client Authentication")

        self.enc_pub_key = None
        self.sig_pub_key = None
        self.sock = None
        self.master_key = None
        self.iv = None
        self.student_id = None
        self.username = None

        self.build_gui()

    def build_gui(self):
        top_frame = tk.Frame(self.root)
        top_frame.pack()

        tk.Label(top_frame, text="Server IP:").grid(row=0, column=0)
        self.ip_entry = tk.Entry(top_frame)
        self.ip_entry.grid(row=0, column=1)
        self.ip_entry.insert(0, "127.0.0.1")

        tk.Label(top_frame, text="Port:").grid(row=1, column=0)
        self.port_entry = tk.Entry(top_frame)
        self.port_entry.grid(row=1, column=1)
        self.port_entry.insert(0, "9999")

        tk.Button(top_frame, text="Load Enc Key", command=self.load_enc_key).grid(row=0, column=2)
        tk.Button(top_frame, text="Load Sig Key", command=self.load_sig_key).grid(row=1, column=2)

        tk.Button(top_frame, text="Connect", command=self.connect).grid(row=2, column=0, columnspan=3)
        tk.Button(top_frame, text="Authenticate", command=self.auth_flow).grid(row=3, column=0, columnspan=3)
        tk.Button(top_frame, text="Delete Account", command=self.delete_account).grid(row=4, column=0, columnspan=3)
        tk.Button(top_frame, text="Disconnect", command=self.disconnect).grid(row=5, column=0, columnspan=3)

        self.message_text = scrolledtext.ScrolledText(self.root, height=10)
        self.message_text.pack()
        self.message_text.insert(tk.END, "Message Window\n")

        self.debug_text = scrolledtext.ScrolledText(self.root, height=20)
        self.debug_text.pack()
        self.debug_text.insert(tk.END, "Debug Window\n")

    def load_enc_key(self):
        filepath = filedialog.askopenfilename()
        with open(filepath, "rb") as f:
            self.enc_pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        self.debug_text.insert(tk.END, f"Loaded Encryption Public Key from: {filepath}\n")

    def load_sig_key(self):
        filepath = filedialog.askopenfilename()
        with open(filepath, "rb") as f:
            self.sig_pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        self.debug_text.insert(tk.END, f"Loaded Signature Public Key from: {filepath}\n")

    def connect(self):
        try:
            ip = self.ip_entry.get()
            port = int(self.port_entry.get())
            self.sock = socket.create_connection((ip, port))
            self.message_text.insert(tk.END, f"Connected to {ip}:{port}\n")
        except Exception as e:
            messagebox.showerror("Connection Failed", str(e))

    def disconnect(self):
        try:
            if self.sock:
                self.sock.close()
                self.sock = None
                self.message_text.insert(tk.END, "Disconnected from server.\n")
        except:
            self.message_text.insert(tk.END, "Disconnection failed.\n")

    def send_with_len(self, data: bytes):
        if not self.sock:
            self.message_text.insert(tk.END, "Not connected to server.\n")
            return
        self.sock.send(len(data).to_bytes(4, 'big') + data)

    def recv_with_len(self):
        length_bytes = self.sock.recv(4)
        if not length_bytes:
            raise ConnectionError("Connection closed by server.")
        length = int.from_bytes(length_bytes, 'big')
        return self.sock.recv(length)

    def verify_signed_message(self, full_msg):
        sig, msg = full_msg[:256], full_msg[256:]
        try:
            self.sig_pub_key.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
            self.debug_text.insert(tk.END, f"Signature verified. Message: {msg.decode()}\n")
            return msg
        except:
            self.message_text.insert(tk.END, "Signature verification failed.\n")
            return None

    def auth_flow(self):
        self.send_with_len(b"auth")
        response = self.recv_with_len()
        msg = self.verify_signed_message(response)
        if not msg: return

        self.student_id = simpledialog.askstring("Student ID", "Enter 5-digit student ID:")
        self.username = simpledialog.askstring("Username", "Enter unique username:")
        self.send_with_len((self.student_id + self.username).encode())

        response = self.recv_with_len()
        msg = self.verify_signed_message(response)
        if not msg: return

        if b"success" in msg.lower():
            code = simpledialog.askstring("Email Code", "Enter 6-digit code sent to your SU email:")
            self.send_with_len(b"code")
            response = self.recv_with_len()
            msg = self.verify_signed_message(response)
            if not msg: return

            code_hash = hashlib.sha512(code.encode()).digest()
            key_iv = os.urandom(32)
            self.master_key = key_iv[:16]
            self.iv = key_iv[16:]

            encrypted = self.enc_pub_key.encrypt(key_iv, padding.PKCS1v15())
            self.debug_text.insert(tk.END, f"KM: {self.master_key.hex()}\nIV: {self.iv.hex()}\nEncrypted KM||IV: {encrypted.hex()}\n")

            final_payload = code_hash + encrypted + (self.student_id + self.username).encode()
            self.send_with_len(final_payload)

            response = self.recv_with_len()
            msg = self.verify_signed_message(response)
            if msg:
                self.message_text.insert(tk.END, "Authentication Completed.\n")
        else:
            self.message_text.insert(tk.END, "Enrollment failed.\n")

    def delete_account(self):
        if not self.sock:
            self.message_text.insert(tk.END, "Not connected.\n")
            return

        self.send_with_len(b"delete")
        response = self.recv_with_len()
        msg = self.verify_signed_message(response)
        if not msg: return

        sid = simpledialog.askstring("Student ID", "Enter your student ID:")
        uname = simpledialog.askstring("Username", "Enter your username:")
        self.send_with_len((sid + uname).encode())

        response = self.recv_with_len()
        msg = self.verify_signed_message(response)
        if not msg: return

        if b"success" in msg.lower():
            rcode = simpledialog.askstring("Removal Code", "Enter 6-digit removal code from your email:")
            self.send_with_len(b"rcode")

            response = self.recv_with_len()
            msg = self.verify_signed_message(response)
            if not msg: return

            self.send_with_len((rcode + sid + uname).encode())

            response = self.recv_with_len()
            msg = self.verify_signed_message(response)
            if msg:
                self.message_text.insert(tk.END, "Account deleted successfully.\n")
        else:
            self.message_text.insert(tk.END, "Deletion failed.\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureClientApp(root)
    root.mainloop()
