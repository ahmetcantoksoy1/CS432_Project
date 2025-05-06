import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import socket
import threading
import hashlib
import os
import time
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

class SecureP2PClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure P2P Client - Step 1")
        self.root.geometry("900x600")
        
        # Server connection parameters
        self.server_socket = None
        self.connected = False
        
        # Cryptographic components
        self.server_enc_key = None  # Server's public key for encryption
        self.server_verify_key = None  # Server's public key for signature verification
        self.master_key = None  # AES master key (128 bits / 16 bytes)
        self.iv = None  # AES IV (128 bits / 16 bytes)
        
        # User info
        self.student_id = ""
        self.username = ""
        self.authenticated = False
        
        # Create the main notebook (tabbed interface)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create the tabs
        self.create_connection_tab()
        self.create_message_tab()
        self.create_debug_tab()
    
    def create_connection_tab(self):
        connection_frame = ttk.Frame(self.notebook)
        self.notebook.add(connection_frame, text="Connection")
        
        # Server key files selection
        key_frame = ttk.LabelFrame(connection_frame, text="Server Public Keys")
        key_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(key_frame, text="Encryption Public Key:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.enc_key_var = tk.StringVar()
        ttk.Entry(key_frame, textvariable=self.enc_key_var, width=40).grid(row=0, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
        ttk.Button(key_frame, text="Browse", command=lambda: self.browse_key_file("enc")).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Label(key_frame, text="Verification Public Key:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.verify_key_var = tk.StringVar()
        ttk.Entry(key_frame, textvariable=self.verify_key_var, width=40).grid(row=1, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
        ttk.Button(key_frame, text="Browse", command=lambda: self.browse_key_file("verify")).grid(row=1, column=2, padx=5, pady=5)
        
        # Server connection form
        server_frame = ttk.LabelFrame(connection_frame, text="Server Connection")
        server_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(server_frame, text="Server IP:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.server_ip_var = tk.StringVar(value="harpoon1.sabanciuniv.edu")
        ttk.Entry(server_frame, textvariable=self.server_ip_var).grid(row=0, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
        
        ttk.Label(server_frame, text="Server Port:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.server_port_var = tk.StringVar(value="9999")
        ttk.Entry(server_frame, textvariable=self.server_port_var).grid(row=1, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
        
        # Connect button
        self.connect_button = ttk.Button(server_frame, text="Connect", command=self.connect_to_server)
        self.connect_button.grid(row=2, column=0, columnspan=2, pady=10)
        
        # Authentication form
        auth_frame = ttk.LabelFrame(connection_frame, text="Authentication")
        auth_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(auth_frame, text="Student ID:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.student_id_var = tk.StringVar()
        ttk.Entry(auth_frame, textvariable=self.student_id_var).grid(row=0, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
        
        ttk.Label(auth_frame, text="Username:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(auth_frame, textvariable=self.username_var).grid(row=1, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
        
        # Auth buttons
        button_frame = ttk.Frame(auth_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        self.start_auth_button = ttk.Button(button_frame, text="Start Authentication", command=self.start_authentication, state=tk.DISABLED)
        self.start_auth_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(auth_frame, text="Email Code:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.code_var = tk.StringVar()
        ttk.Entry(auth_frame, textvariable=self.code_var).grid(row=3, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
        
        self.verify_code_button = ttk.Button(auth_frame, text="Verify Code", command=self.verify_code, state=tk.DISABLED)
        self.verify_code_button.grid(row=4, column=0, columnspan=2, pady=10)
        
        # Deletion form
        delete_frame = ttk.LabelFrame(connection_frame, text="Delete Account")
        delete_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.start_delete_button = ttk.Button(delete_frame, text="Start Deletion Process", command=self.start_deletion, state=tk.DISABLED)
        self.start_delete_button.pack(pady=10)
        
        ttk.Label(delete_frame, text="Removal Code:").pack(side=tk.LEFT, padx=5, pady=5)
        self.rcode_var = tk.StringVar()
        ttk.Entry(delete_frame, textvariable=self.rcode_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        
        self.delete_account_button = ttk.Button(delete_frame, text="Delete Account", command=self.delete_account, state=tk.DISABLED)
        self.delete_account_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Disconnect button
        self.disconnect_button = ttk.Button(connection_frame, text="Disconnect", command=self.disconnect_from_server, state=tk.DISABLED)
        self.disconnect_button.pack(pady=10)
    
    def create_message_tab(self):
        message_frame = ttk.Frame(self.notebook)
        self.notebook.add(message_frame, text="Message")
        
        # Message display
        self.message_display = scrolledtext.ScrolledText(message_frame, wrap=tk.WORD, width=40, height=20)
        self.message_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.message_display.config(state=tk.DISABLED)
    
    def create_debug_tab(self):
        debug_frame = ttk.Frame(self.notebook)
        self.notebook.add(debug_frame, text="Debug")
        
        self.debug_display = scrolledtext.ScrolledText(debug_frame, wrap=tk.WORD, width=40, height=20)
        self.debug_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.debug_display.config(state=tk.DISABLED)
    
    def browse_key_file(self, key_type):
        file_path = filedialog.askopenfilename(
            title=f"Select Server's {key_type.capitalize()} Public Key",
            filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")]
        )
        
        if file_path:
            if key_type == "enc":
                self.enc_key_var.set(file_path)
                try:
                    self.load_encryption_key(file_path)
                except Exception as e:
                    self.display_error(f"Failed to load encryption key: {str(e)}")
            else:
                self.verify_key_var.set(file_path)
                try:
                    self.load_verification_key(file_path)
                except Exception as e:
                    self.display_error(f"Failed to load verification key: {str(e)}")
    
    def load_encryption_key(self, file_path):
        with open(file_path, "rb") as f:
            self.server_enc_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        
        self.log_to_debug("Server Encryption Public Key loaded successfully")
        key_hex = self.server_enc_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()
        self.log_to_debug(f"Encryption Key (Hex): {key_hex}")
    
    def load_verification_key(self, file_path):
        with open(file_path, "rb") as f:
            self.server_verify_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        
        self.log_to_debug("Server Verification Public Key loaded successfully")
        key_hex = self.server_verify_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()
        self.log_to_debug(f"Verification Key (Hex): {key_hex}")
    
    def connect_to_server(self):
        if not self.server_enc_key or not self.server_verify_key:
            self.display_error("Please load both server public keys first")
            return
        
        server_ip = self.server_ip_var.get()
        try:
            server_port = int(self.server_port_var.get())
        except ValueError:
            self.display_error("Server port must be a valid number")
            return
        
        try:
            self.log_to_message(f"Connecting to server at {server_ip}:{server_port}...")
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.connect((server_ip, server_port))
            self.connected = True
            
            self.log_to_message("Connected to server successfully")
            self.log_to_debug(f"Connected to {server_ip}:{server_port}")
            
            # Enable authentication button and disable connect button
            self.connect_button.config(state=tk.DISABLED)
            self.start_auth_button.config(state=tk.NORMAL)
            self.disconnect_button.config(state=tk.NORMAL)
            self.start_delete_button.config(state=tk.NORMAL)
            
            # Start a thread to handle server messages
            threading.Thread(target=self.receive_server_messages, daemon=True).start()
        
        except Exception as e:
            self.display_error(f"Failed to connect to server: {str(e)}")
    
    def start_authentication(self):
        if not self.connected:
            self.display_error("Not connected to server")
            return
        
        self.student_id = self.student_id_var.get()
        self.username = self.username_var.get()
        
        if not self.student_id or not self.username:
            self.display_error("Student ID and username cannot be empty")
            return
        
        try:
            # Start authentication process
            self.log_to_message("Starting authentication process...")
            self.log_to_debug("Sending 'auth' to server")
            
            # Send "auth" to the server
            self.server_socket.sendall(b"auth")
            
            # Wait for the server's response (handled by receive_server_messages)
            self.verify_code_button.config(state=tk.NORMAL)
            
        except Exception as e:
            self.display_error(f"Authentication failed: {str(e)}")
    
    def verify_code(self):
        if not self.connected:
            self.display_error("Not connected to server")
            return
        
        code = self.code_var.get()
        
        if not code:
            self.display_error("Please enter the email code")
            return
        
        try:
            # Send "code" to the server
            self.log_to_message("Initiating code verification...")
            self.log_to_debug("Sending 'code' to server")
            self.server_socket.sendall(b"code")
            
            # Generate hash of the code
            code_hash = hashlib.sha512(code.encode()).digest()
            self.log_to_debug(f"Generated SHA-512 hash of code: {code_hash.hex()}")
            
            # Generate random 32 bytes for KM and IV
            random_bytes = os.urandom(32)
            self.master_key = random_bytes[:16]  # First 16 bytes for Master Key
            self.iv = random_bytes[16:]  # Last 16 bytes for IV
            
            self.log_to_debug(f"Generated Master Key (KM): {self.master_key.hex()}")
            self.log_to_debug(f"Generated IV: {self.iv.hex()}")
            
            # Encrypt (KM || IV) with server's public key
            encrypted_key_iv = self.server_enc_key.encrypt(
                random_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            self.log_to_debug(f"Encrypted (KM || IV): {encrypted_key_iv.hex()}")
            
            # Wait for server's response to "code" message
            # After receiving response in receive_server_messages, we'll send hash and encrypted key
            
        except Exception as e:
            self.display_error(f"Code verification failed: {str(e)}")
    
    def start_deletion(self):
        if not self.connected:
            self.display_error("Not connected to server")
            return
        
        try:
            # Send "delete" to the server
            self.log_to_message("Starting deletion process...")
            self.log_to_debug("Sending 'delete' to server")
            self.server_socket.sendall(b"delete")
            
            # Wait for the server's response (handled by receive_server_messages)
            self.delete_account_button.config(state=tk.NORMAL)
            
        except Exception as e:
            self.display_error(f"Deletion process failed: {str(e)}")
    
    def delete_account(self):
        if not self.connected:
            self.display_error("Not connected to server")
            return
        
        rcode = self.rcode_var.get()
        
        if not rcode:
            self.display_error("Please enter the removal code")
            return
        
        try:
            # Send "rcode" to the server
            self.log_to_message("Verifying removal code...")
            self.log_to_debug("Sending 'rcode' to server")
            self.server_socket.sendall(b"rcode")
            
            # The actual deletion will happen after server confirmation in receive_server_messages
            
        except Exception as e:
            self.display_error(f"Account deletion failed: {str(e)}")
    
    def handle_server_auth_response(self, data):
        # Extract signature and message
        signature_size = 256  # 2048-bit RSA signature is 256 bytes
        signature = data[:signature_size]
        message = data[signature_size:]
        
        self.log_to_debug(f"Received signature (Hex): {signature.hex()}")
        self.log_to_debug(f"Received message: {message.decode()}")
        
        # Verify signature
        try:
            self.server_verify_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            self.log_to_debug("Signature verification: SUCCESS")
            
            # Parse the message
            message_str = message.decode()
            if "Successfully starting auth flow" in message_str:
                self.log_to_message("Server authenticated successfully. Sending ID and username...")
                
                # Send student ID and username
                auth_data = f"{self.student_id}{self.username}".encode()
                self.log_to_debug(f"Sending ID and username: {auth_data}")
                self.server_socket.sendall(auth_data)
                
            elif "success" in message_str.lower():
                self.log_to_message("Authentication step completed successfully")
                self.log_to_message("Please check your email for the verification code")
                
            elif "error" in message_str.lower():
                self.log_to_message(f"Server returned an error: {message_str}")
                
        except Exception as e:
            self.log_to_debug(f"Signature verification: FAILED - {str(e)}")
            self.display_error("Server signature verification failed. Possible security breach!")
    
    def handle_server_code_response(self, data):
        # Extract signature and message
        signature_size = 256  # 2048-bit RSA signature is 256 bytes
        signature = data[:signature_size]
        message = data[signature_size:]
        
        self.log_to_debug(f"Received signature (Hex): {signature.hex()}")
        self.log_to_debug(f"Received message: {message.decode()}")
        
        # Verify signature
        try:
            self.server_verify_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            self.log_to_debug("Signature verification: SUCCESS")
            
            # Parse the message
            message_str = message.decode()
            if "success" in message_str.lower():
                self.log_to_message("Code verification initiated successfully")
                
                # Get the code entered by the user
                code = self.code_var.get()
                
                # Generate hash of the code
                code_hash = hashlib.sha512(code.encode()).digest()
                
                # Prepare the message: <hash of the code><RSAE(KM || IV)><student ID><username>
                encrypted_key_iv = self.server_enc_key.encrypt(
                    self.master_key + self.iv,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                auth_data = code_hash + encrypted_key_iv + self.student_id.encode() + self.username.encode()
                self.log_to_debug(f"Sending code hash and encrypted key: {auth_data[:20].hex()}...")
                self.server_socket.sendall(auth_data)
                
            elif "error" in message_str.lower():
                self.log_to_message(f"Server returned an error: {message_str}")
                
        except Exception as e:
            self.log_to_debug(f"Signature verification: FAILED - {str(e)}")
            self.display_error("Server signature verification failed. Possible security breach!")
    
    def handle_server_delete_response(self, data):
        # Extract signature and message
        signature_size = 256  # 2048-bit RSA signature is 256 bytes
        signature = data[:signature_size]
        message = data[signature_size:]
        
        self.log_to_debug(f"Received signature (Hex): {signature.hex()}")
        self.log_to_debug(f"Received message: {message.decode()}")
        
        # Verify signature
        try:
            self.server_verify_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            self.log_to_debug("Signature verification: SUCCESS")
            
            # Parse the message
            message_str = message.decode()
            if "success" in message_str.lower():
                self.log_to_message("Deletion process initiated successfully")
                
                # Send student ID and username
                delete_data = f"{self.student_id}{self.username}".encode()
                self.log_to_debug(f"Sending ID and username for deletion: {delete_data}")
                self.server_socket.sendall(delete_data)
                
            elif "error" in message_str.lower():
                self.log_to_message(f"Server returned an error: {message_str}")
                
        except Exception as e:
            self.log_to_debug(f"Signature verification: FAILED - {str(e)}")
            self.display_error("Server signature verification failed. Possible security breach!")
    
    def handle_server_rcode_response(self, data):
        # Extract signature and message
        signature_size = 256  # 2048-bit RSA signature is 256 bytes
        signature = data[:signature_size]
        message = data[signature_size:]
        
        self.log_to_debug(f"Received signature (Hex): {signature.hex()}")
        self.log_to_debug(f"Received message: {message.decode()}")
        
        # Verify signature
        try:
            self.server_verify_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            self.log_to_debug("Signature verification: SUCCESS")
            
            # Parse the message
            message_str = message.decode()
            if "success" in message_str.lower():
                self.log_to_message("Removal code verification initiated successfully")
                
                # Get the removal code entered by the user
                rcode = self.rcode_var.get()
                
                # Send the rcode, student ID, and username
                delete_data = f"{rcode}{self.student_id}{self.username}".encode()
                self.log_to_debug(f"Sending removal code and account info: {delete_data}")
                self.server_socket.sendall(delete_data)
                
            elif "error" in message_str.lower():
                self.log_to_message(f"Server returned an error: {message_str}")
                
        except Exception as e:
            self.log_to_debug(f"Signature verification: FAILED - {str(e)}")
            self.display_error("Server signature verification failed. Possible security breach!")
    
    def handle_server_auth_result(self, data):
        # Extract signature and message
        signature_size = 256  # 2048-bit RSA signature is 256 bytes
        signature = data[:signature_size]
        message = data[signature_size:]
        
        self.log_to_debug(f"Received auth result signature (Hex): {signature.hex()}")
        self.log_to_debug(f"Received auth result message: {message.decode()}")
        
        # Verify signature
        try:
            self.server_verify_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            self.log_to_debug("Signature verification: SUCCESS")
            
            # Parse the message
            message_str = message.decode()
            if "Authentication Successful" in message_str:
                self.log_to_message("Authentication completed successfully!")
                self.authenticated = True
                messagebox.showinfo("Success", "Authentication completed successfully!\n\nMaster Key and IV have been generated and saved. Keep them safe as you will need them for future communications with the server.")
                
                # Save the master key and IV to a file for future use
                self.save_key_and_iv()
                
            else:
                self.log_to_message(f"Authentication failed: {message_str}")
                
        except Exception as e:
            self.log_to_debug(f"Signature verification: FAILED - {str(e)}")
            self.display_error("Server signature verification failed. Possible security breach!")
    
    def handle_server_delete_result(self, data):
        # Extract signature and message
        signature_size = 256  # 2048-bit RSA signature is 256 bytes
        signature = data[:signature_size]
        message = data[signature_size:]
        
        self.log_to_debug(f"Received delete result signature (Hex): {signature.hex()}")
        self.log_to_debug(f"Received delete result message: {message.decode()}")
        
        # Verify signature
        try:
            self.server_verify_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            self.log_to_debug("Signature verification: SUCCESS")
            
            # Parse the message
            message_str = message.decode()
            if "success" in message_str.lower():
                self.log_to_message("Account deleted successfully!")
                messagebox.showinfo("Success", "Your account has been deleted successfully.")
                
            else:
                self.log_to_message(f"Account deletion failed: {message_str}")
                
        except Exception as e:
            self.log_to_debug(f"Signature verification: FAILED - {str(e)}")
            self.display_error("Server signature verification failed. Possible security breach!")
    
    def save_key_and_iv(self):
        try:
            file_path = filedialog.asksaveasfilename(
                title="Save Master Key and IV",
                defaultextension=".key",
                filetypes=[("Key Files", "*.key"), ("All Files", "*.*")]
            )
            
            if file_path:
                with open(file_path, "wb") as f:
                    f.write(self.master_key + self.iv)
                
                self.log_to_message(f"Master Key and IV saved to {file_path}")
                self.log_to_debug(f"Saved KM: {self.master_key.hex()}")
                self.log_to_debug(f"Saved IV: {self.iv.hex()}")
        
        except Exception as e:
            self.display_error(f"Failed to save key: {str(e)}")
    
    def receive_server_messages(self):
        buffer = b""
        expecting_auth_response = False
        expecting_code_response = False
        expecting_delete_response = False
        expecting_rcode_response = False
        
        while self.connected:
            try:
                data = self.server_socket.recv(4096)
                if not data:
                    # Connection closed by server
                    self.log_to_message("Server disconnected")
                    self.connected = False
                    self.disconnect_from_server()
                    break
                
                buffer += data
                
                # Determine what kind of response we are expecting
                # This is a simplified state machine for demonstration
                # In a real application, you'd have a more robust message handling system
                
                if not expecting_auth_response and not expecting_code_response and not expecting_delete_response and not expecting_rcode_response:
                    # We just sent a command, determine what response to expect
                    message = buffer.decode(errors='ignore')
                    if "auth" in message:
                        expecting_auth_response = True
                    elif "code" in message:
                        expecting_code_response = True
                    elif "delete" in message:
                        expecting_delete_response = True
                    elif "rcode" in message:
                        expecting_rcode_response = True
                
                # Process the buffer based on what we're expecting
                if expecting_auth_response and len(buffer) >= 256:  # At least contains a signature
                    self.handle_server_auth_response(buffer)
                    buffer = b""
                    expecting_auth_response = False
                
                elif expecting_code_response and len(buffer) >= 256:
                    self.handle_server_code_response(buffer)
                    buffer = b""
                    expecting_code_response = False
                
                elif expecting_delete_response and len(buffer) >= 256:
                    self.handle_server_delete_response(buffer)
                    buffer = b""
                    expecting_delete_response = False
                
                elif expecting_rcode_response and len(buffer) >= 256:
                    self.handle_server_rcode_response(buffer)
                    buffer = b""
                    expecting_rcode_response = False
                
                # Check if we received an authentication result
                elif "Authentication Successful" in buffer.decode(errors='ignore') or "Authentication Unsuccessful" in buffer.decode(errors='ignore'):
                    self.handle_server_auth_result(buffer)
                    buffer = b""
                
                # Check if we received a deletion result
                elif "success" in buffer.decode(errors='ignore').lower() and "delete" in buffer.decode(errors='ignore').lower():
                    self.handle_server_delete_result(buffer)
                    buffer = b""
                
            except OSError:
                # Socket closed or error
                if self.connected:
                    self.log_to_message("Connection to server lost")
                    self.connected = False
                    self.disconnect_from_server()
                break
            
            except Exception as e:
                self.log_to_debug(f"Error receiving messages: {str(e)}")
    
    def disconnect_from_server(self):
        """Disconnect from the server and reset UI state"""
        if self.server_socket:
            try:
                self.server_socket.close()
                self.server_socket = None
            except:
                pass
            
        self.connected = False
        self.authenticated = False
        self.last_command = None
        self.waiting_for_response = False
        
        # Update UI
        self.connect_button.config(state=tk.NORMAL)
        self.start_auth_button.config(state=tk.DISABLED)
        self.verify_code_button.config(state=tk.DISABLED)
        self.disconnect_button.config(state=tk.DISABLED)
        self.start_delete_button.config(state=tk.DISABLED)
        self.delete_account_button.config(state=tk.DISABLED)
        
        self.log_to_message("Disconnected from server")
    
    def log_to_message(self, message):
        """Add a message to the message display"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        # Update the message display in the main thread
        self.root.after(0, self._update_message, log_entry)
    
    def _update_message(self, message):
        """Update the message display (must be called from the main thread)"""
        self.message_display.config(state=tk.NORMAL)
        self.message_display.insert(tk.END, message)
        self.message_display.see(tk.END)
        self.message_display.config(state=tk.DISABLED)
    
    def log_to_debug(self, message):
        """Add a message to the debug display"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        # Update the debug display in the main thread
        self.root.after(0, self._update_debug, log_entry)
    
    def _update_debug(self, message):
        """Update the debug display (must be called from the main thread)"""
        self.debug_display.config(state=tk.NORMAL)
        self.debug_display.insert(tk.END, message)
        self.debug_display.see(tk.END)
        self.debug_display.config(state=tk.DISABLED)
    
    def display_error(self, message):
        """Display an error message in a dialog and log it"""
        messagebox.showerror("Error", message)
        self.log_to_debug(f"ERROR: {message}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureP2PClient(root)
    root.mainloop()