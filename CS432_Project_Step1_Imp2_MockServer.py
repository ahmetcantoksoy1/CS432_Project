import tkinter as tk
from tkinter import ttk, scrolledtext
import socket
import threading
import os
import time
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

class UserAccount:
    def __init__(self, student_id, username, email=None):
        self.student_id = student_id
        self.username = username
        self.email = email or f"{student_id}@sabanciuniv.edu"
        self.code = None  # 6-digit authentication code
        self.rcode = None  # 6-digit removal code
        self.master_key = None
        self.iv = None
        self.authenticated = False

class MockServer:
    def __init__(self, root):
        self.root = root
        self.root.title("Mock Server for Testing")
        self.root.geometry("800x600")
        
        # Server socket
        self.server_socket = None
        self.is_running = False
        self.clients = {}  # Dictionary to store client connections
        
        # Cryptographic components
        self.signing_key = None
        self.decryption_key = None
        
        # User database (in-memory for this demo)
        self.user_database = {}  # {student_id: {username: UserAccount}}
        
        # Create the main frame
        main_frame = ttk.Frame(root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create a notebook (tabbed interface)
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Server control tab
        control_frame = ttk.Frame(self.notebook)
        self.notebook.add(control_frame, text="Server Control")
        
        # Port entry
        ttk.Label(control_frame, text="Server Port:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.port_var = tk.StringVar(value="9999")
        ttk.Entry(control_frame, textvariable=self.port_var, width=6).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Generate keys button
        ttk.Button(control_frame, text="Generate Keys", command=self.generate_keys).grid(row=1, column=0, columnspan=2, pady=5)
        
        # Start/Stop server buttons
        self.start_button = ttk.Button(control_frame, text="Start Server", command=self.start_server)
        self.start_button.grid(row=2, column=0, pady=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop Server", command=self.stop_server, state=tk.DISABLED)
        self.stop_button.grid(row=2, column=1, pady=5)
        
        # Log tab
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="Server Log")
        
        self.log_display = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD)
        self.log_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_display.config(state=tk.DISABLED)
        
        # Users tab
        users_frame = ttk.Frame(self.notebook)
        self.notebook.add(users_frame, text="Users")
        
        self.users_display = scrolledtext.ScrolledText(users_frame, wrap=tk.WORD)
        self.users_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.users_display.config(state=tk.DISABLED)
        
        # Generate keys on startup
        self.generate_keys()
    
    def generate_keys(self):
        """Generate RSA key pairs for the server"""
        self.log("Generating RSA key pairs...")
        
        # Generate signing/verification key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.signing_key = private_key
        verify_key = private_key.public_key()
        
        # Generate encryption/decryption key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.decryption_key = private_key
        encrypt_key = private_key.public_key()
        
        # Save public keys to files
        with open("server_sign_verify_pub.pem", "wb") as f:
            f.write(verify_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        
        with open("server_enc_dec_pub.pem", "wb") as f:
            f.write(encrypt_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        
        self.log("RSA key pairs generated successfully")
        self.log("Public keys saved to server_sign_verify_pub.pem and server_enc_dec_pub.pem")
    
    def start_server(self):
        """Start the server"""
        if not self.signing_key or not self.decryption_key:
            self.log("ERROR: Keys not generated")
            return
        
        try:
            port = int(self.port_var.get())
            
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', port))
            self.server_socket.listen(5)
            
            self.is_running = True
            self.log(f"Server started on port {port}")
            
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            
            # Start accepting connections in a separate thread
            threading.Thread(target=self.accept_connections, daemon=True).start()
            
        except Exception as e:
            self.log(f"ERROR: Failed to start server - {str(e)}")
    
    def stop_server(self):
        """Stop the server"""
        self.is_running = False
        
        # Close all client connections
        for client_socket in self.clients.values():
            try:
                client_socket.close()
            except:
                pass
        
        # Close server socket
        if self.server_socket:
            self.server_socket.close()
        
        self.log("Server stopped")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
    
    def accept_connections(self):
        """Accept incoming client connections"""
        while self.is_running:
            try:
                client_socket, address = self.server_socket.accept()
                client_address = f"{address[0]}:{address[1]}"
                self.clients[client_address] = client_socket
                
                self.log(f"New client connected: {client_address}")
                
                # Handle this client in a separate thread
                threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address),
                    daemon=True
                ).start()
                
            except OSError:
                # Socket closed or error
                if self.is_running:
                    self.log("ERROR: Error accepting connection")
                break
    
    def handle_client(self, client_socket, client_address):
        """Handle communication with a client"""
        current_student_id = None
        current_username = None
        current_step = "initial"  # Tracks the current step in the authentication process
        
        try:
            while self.is_running:
                # Receive data from client
                data = client_socket.recv(4096)
                if not data:
                    # Client disconnected
                    self.log(f"Client disconnected: {client_address}")
                    break
                
                # Process the received data based on the current step
                message = data.decode(errors='ignore')
                self.log(f"Received from {client_address}: {message[:50]}")
                
                if current_step == "initial":
                    if message == "auth":
                        # Start authentication process
                        self.log(f"Starting authentication flow for {client_address}")
                        
                        # Send signed response
                        response = "Successfully starting auth flow."
                        signature = self.signing_key.sign(
                            response.encode(),
                            padding.PKCS1v15(),
                            hashes.SHA256()
                        )
                        client_socket.sendall(signature + response.encode())
                        
                        current_step = "waiting_id_username"
                    
                    elif message == "delete":
                        # Start deletion process
                        self.log(f"Starting deletion process for {client_address}")
                        
                        # Send signed response
                        response = "Successfully starting deletion flow."
                        signature = self.signing_key.sign(
                            response.encode(),
                            padding.PKCS1v15(),
                            hashes.SHA256()
                        )
                        client_socket.sendall(signature + response.encode())
                        
                        current_step = "waiting_delete_id_username"
                        
                    else:
                        self.log(f"Unexpected initial message: {message}")
                
                elif current_step == "waiting_id_username":
                    # Extract student ID and username
                    # In a real implementation, you'd have more robust parsing
                    student_id = message[:5]  # Assuming 5-digit student ID
                    username = message[5:]
                    
                    self.log(f"Received ID: {student_id}, Username: {username}")
                    
                    # Validate student ID (simplified for demo - just check if it's 5 digits)
                    if not (student_id.isdigit() and len(student_id) == 5):
                        response = "Error: Invalid student ID. Must be 5 digits."
                        signature = self.signing_key.sign(
                            response.encode(),
                            padding.PKCS1v15(),
                            hashes.SHA256()
                        )
                        client_socket.sendall(signature + response.encode())
                        current_step = "initial"
                        continue
                    
                    # Check if student has reached the maximum number of accounts (5)
                    if student_id in self.user_database and len(self.user_database[student_id]) >= 5:
                        response = "Error: Maximum number of accounts (5) reached for this student ID."
                        signature = self.signing_key.sign(
                            response.encode(),
                            padding.PKCS1v15(),
                            hashes.SHA256()
                        )
                        client_socket.sendall(signature + response.encode())
                        current_step = "initial"
                        continue
                    
                    # Check if username is already in use for this student
                    if student_id in self.user_database and username in self.user_database[student_id]:
                        response = "Error: Username already in use for this student ID."
                        signature = self.signing_key.sign(
                            response.encode(),
                            padding.PKCS1v15(),
                            hashes.SHA256()
                        )
                        client_socket.sendall(signature + response.encode())
                        current_step = "initial"
                        continue
                    
                    # If we get here, the ID and username are valid
                    # Initialize the user database entry if needed
                    if student_id not in self.user_database:
                        self.user_database[student_id] = {}
                    
                    # Create a new account
                    account = UserAccount(student_id, username)
                    self.user_database[student_id][username] = account
                    
                    # Generate a 6-digit code
                    account.code = str(os.urandom(3).hex())[:6]
                    
                    self.log(f"Generated verification code for {student_id}/{username}: {account.code}")
                    self.update_users_display()
                    
                    # In a real implementation, you'd send an email here
                    # For this mock server, we'll just log the code
                    self.log(f"Would send email to {account.email} with code: {account.code}")
                    
                    # Send success response
                    response = f"Success: Account registered. Check your email ({account.email}) for the verification code."
                    signature = self.signing_key.sign(
                        response.encode(),
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
                    client_socket.sendall(signature + response.encode())
                    
                    current_student_id = student_id
                    current_username = username
                    current_step = "waiting_code"
                
                elif current_step == "waiting_code":
                    if message == "code":
                        # Client is ready to send the verification code
                        self.log(f"Client {client_address} initiating code verification")
                        
                        # Send signed response
                        response = "Success: Ready for code verification."
                        signature = self.signing_key.sign(
                            response.encode(),
                            padding.PKCS1v15(),
                            hashes.SHA256()
                        )
                        client_socket.sendall(signature + response.encode())
                        
                        current_step = "waiting_code_verification"
                    else:
                        self.log(f"Unexpected message in waiting_code state: {message}")
                
                elif current_step == "waiting_code_verification":
                    # Extract hash of code, encrypted key+IV, student ID, and username
                    # In a real implementation, you'd have more robust parsing
                    try:
                        hash_size = 64  # SHA-512 hash is 64 bytes
                        code_hash = data[:hash_size]
                        
                        # Skip the encrypted key+IV part for this mock implementation
                        # In a real implementation, you'd decrypt this to get the master key and IV
                        
                        # Just for demo purposes, extract the encrypted part
                        encrypted_size = 256  # 2048-bit RSA encrypted data is 256 bytes
                        encrypted_key_iv = data[hash_size:hash_size+encrypted_size]
                        
                        # The rest is student ID and username
                        remaining = data[hash_size+encrypted_size:].decode()
                        student_id = remaining[:5]  # Assuming 5-digit student ID
                        username = remaining[5:]
                        
                        self.log(f"Received verification data: Hash={code_hash.hex()[:10]}..., " +
                                f"Encrypted={encrypted_key_iv.hex()[:10]}..., " +
                                f"ID={student_id}, Username={username}")
                        
                        # Verify student ID and username match what we expect
                        if student_id != current_student_id or username != current_username:
                            response = "Error: Student ID or username mismatch."
                            signature = self.signing_key.sign(
                                response.encode(),
                                padding.PKCS1v15(),
                                hashes.SHA256()
                            )
                            client_socket.sendall(signature + response.encode())
                            current_step = "initial"
                            continue
                        
                        # Get the account and calculate expected hash
                        account = self.user_database[student_id][username]
                        expected_hash = hashlib.sha512(account.code.encode()).digest()
                        
                        # Verify the hash
                        if code_hash == expected_hash:
                            # Hash is correct, decrypt the master key and IV
                            try:
                                key_iv = self.decryption_key.decrypt(
                                    encrypted_key_iv,
                                    padding.OAEP(
                                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None
                                    )
                                )
                                
                                # Split into master key and IV
                                account.master_key = key_iv[:16]
                                account.iv = key_iv[16:]
                                account.authenticated = True
                                
                                self.log(f"Authentication successful for {student_id}/{username}")
                                self.log(f"Master Key: {account.master_key.hex()}")
                                self.log(f"IV: {account.iv.hex()}")
                                self.update_users_display()
                                
                                # Send success response
                                response = "Authentication Successful"
                                signature = self.signing_key.sign(
                                    response.encode(),
                                    padding.PKCS1v15(),
                                    hashes.SHA256()
                                )
                                client_socket.sendall(signature + response.encode())
                                
                            except Exception as e:
                                self.log(f"Error decrypting key+IV: {str(e)}")
                                response = "Authentication Unsuccessful: Failed to decrypt key and IV."
                                signature = self.signing_key.sign(
                                    response.encode(),
                                    padding.PKCS1v15(),
                                    hashes.SHA256()
                                )
                                client_socket.sendall(signature + response.encode())
                            
                        else:
                            self.log(f"Authentication failed: Invalid code hash")
                            response = "Authentication Unsuccessful: Invalid verification code."
                            signature = self.signing_key.sign(
                                response.encode(),
                                padding.PKCS1v15(),
                                hashes.SHA256()
                            )
                            client_socket.sendall(signature + response.encode())
                        
                        # Reset to initial state after authentication attempt
                        current_step = "initial"
                        
                    except Exception as e:
                        self.log(f"Error processing verification data: {str(e)}")
                        response = "Error: Invalid verification data format."
                        signature = self.signing_key.sign(
                            response.encode(),
                            padding.PKCS1v15(),
                            hashes.SHA256()
                        )
                        client_socket.sendall(signature + response.encode())
                        current_step = "initial"
                
                elif current_step == "waiting_delete_id_username":
                    # Extract student ID and username
                    student_id = message[:5]  # Assuming 5-digit student ID
                    username = message[5:]
                    
                    self.log(f"Received delete request for ID: {student_id}, Username: {username}")
                    
                    # Check if account exists
                    if (student_id not in self.user_database or 
                        username not in self.user_database[student_id]):
                        response = "Error: Account not found."
                        signature = self.signing_key.sign(
                            response.encode(),
                            padding.PKCS1v15(),
                            hashes.SHA256()
                        )
                        client_socket.sendall(signature + response.encode())
                        current_step = "initial"
                        continue
                    
                    # Generate a removal code
                    account = self.user_database[student_id][username]
                    account.rcode = str(os.urandom(3).hex())[:6]
                    
                    self.log(f"Generated removal code for {student_id}/{username}: {account.rcode}")
                    
                    # In a real implementation, you'd send an email here
                    self.log(f"Would send email to {account.email} with removal code: {account.rcode}")
                    
                    # Send success response
                    response = f"Success: Check your email ({account.email}) for the removal code."
                    signature = self.signing_key.sign(
                        response.encode(),
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
                    client_socket.sendall(signature + response.encode())
                    
                    current_student_id = student_id
                    current_username = username
                    current_step = "waiting_rcode"
                
                elif current_step == "waiting_rcode":
                    if message == "rcode":
                        # Client is ready to send the removal code
                        self.log(f"Client {client_address} initiating removal code verification")
                        
                        # Send signed response
                        response = "Success: Ready for removal code verification."
                        signature = self.signing_key.sign(
                            response.encode(),
                            padding.PKCS1v15(),
                            hashes.SHA256()
                        )
                        client_socket.sendall(signature + response.encode())
                        
                        current_step = "waiting_rcode_verification"
                    else:
                        self.log(f"Unexpected message in waiting_rcode state: {message}")
                
                elif current_step == "waiting_rcode_verification":
                    # Extract rcode, student ID, and username
                    try:
                        rcode = message[:6]  # Assuming 6-digit removal code
                        student_id = message[6:11]  # Assuming 5-digit student ID
                        username = message[11:]
                        
                        self.log(f"Received removal data: RCode={rcode}, ID={student_id}, Username={username}")
                        
                        # Verify student ID and username match what we expect
                        if student_id != current_student_id or username != current_username:
                            response = "Error: Student ID or username mismatch."
                            signature = self.signing_key.sign(
                                response.encode(),
                                padding.PKCS1v15(),
                                hashes.SHA256()
                            )
                            client_socket.sendall(signature + response.encode())
                            current_step = "initial"
                            continue
                        
                        # Check if account exists
                        if (student_id not in self.user_database or 
                            username not in self.user_database[student_id]):
                            response = "Error: Account not found."
                            signature = self.signing_key.sign(
                                response.encode(),
                                padding.PKCS1v15(),
                                hashes.SHA256()
                            )
                            client_socket.sendall(signature + response.encode())
                            current_step = "initial"
                            continue
                        
                        # Verify the removal code
                        account = self.user_database[student_id][username]
                        if rcode == account.rcode:
                            # Code is correct, delete the account
                            del self.user_database[student_id][username]
                            if not self.user_database[student_id]:
                                del self.user_database[student_id]
                            
                            self.log(f"Account deleted: {student_id}/{username}")
                            self.update_users_display()
                            
                            # Send success response
                            response = "Success: Account deleted successfully."
                            signature = self.signing_key.sign(
                                response.encode(),
                                padding.PKCS1v15(),
                                hashes.SHA256()
                            )
                            client_socket.sendall(signature + response.encode())
                            
                        else:
                            self.log(f"Account deletion failed: Invalid removal code")
                            response = "Error: Invalid removal code."
                            signature = self.signing_key.sign(
                                response.encode(),
                                padding.PKCS1v15(),
                                hashes.SHA256()
                            )
                            client_socket.sendall(signature + response.encode())
                        
                        # Reset to initial state after deletion attempt
                        current_step = "initial"
                        
                    except Exception as e:
                        self.log(f"Error processing removal data: {str(e)}")
                        response = "Error: Invalid removal data format."
                        signature = self.signing_key.sign(
                            response.encode(),
                            padding.PKCS1v15(),
                            hashes.SHA256()
                        )
                        client_socket.sendall(signature + response.encode())
                        current_step = "initial"
                
                else:
                    self.log(f"Unknown state: {current_step}")
        
        except Exception as e:
            self.log(f"Error handling client {client_address}: {str(e)}")
        
        finally:
            # Cleanup
            try:
                client_socket.close()
                del self.clients[client_address]
                self.log(f"Client disconnected: {client_address}")
            except:
                pass
    
    def log(self, message):
        """Add a message to the log display"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        # Update the log display in the main thread
        self.root.after(0, self._update_log, log_entry)
    
    def _update_log(self, message):
        """Update the log display (must be called from the main thread)"""
        self.log_display.config(state=tk.NORMAL)
        self.log_display.insert(tk.END, message)
        self.log_display.see(tk.END)
        self.log_display.config(state=tk.DISABLED)
    
    def update_users_display(self):
        """Update the users display with current user database"""
        self.users_display.config(state=tk.NORMAL)
        self.users_display.delete(1.0, tk.END)
        
        for student_id, accounts in self.user_database.items():
            self.users_display.insert(tk.END, f"Student ID: {student_id}\n")
            for username, account in accounts.items():
                self.users_display.insert(tk.END, f"  Username: {username}\n")
                self.users_display.insert(tk.END, f"  Email: {account.email}\n")
                self.users_display.insert(tk.END, f"  Code: {account.code}\n")
                self.users_display.insert(tk.END, f"  RCode: {account.rcode}\n")
                self.users_display.insert(tk.END, f"  Authenticated: {account.authenticated}\n")
                if account.authenticated:
                    self.users_display.insert(tk.END, f"  Master Key: {account.master_key.hex() if account.master_key else 'None'}\n")
                    self.users_display.insert(tk.END, f"  IV: {account.iv.hex() if account.iv else 'None'}\n")
                self.users_display.insert(tk.END, "\n")
        
        self.users_display.see(tk.END)
        self.users_display.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = MockServer(root)
    root.mainloop()