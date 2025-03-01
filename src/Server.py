from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import json

class Server:
    def __init__(self):
        # Initialize RSA keys
        self.private_key = None
        self.public_key = None
        self.load_rsa_keys()
        
        # Initialize user database
        self.user_db = {}
        self.load_from_file()

    def load_rsa_keys(self):
        """ Load RSA private and public keys """
        try:
            with open("private.pem", "rb") as f:
                self.private_key = RSA.import_key(f.read())
            with open("public.pem", "rb") as f:
                self.public_key = RSA.import_key(f.read())
            print("RSA keys loaded successfully.") 
        except Exception as e:
            print(f"Error loading RSA keys: {e}")
            raise e
        
    def load_from_file(self):
        """ Load user data from an encrypted file into memory """
        try:
            with open("database.txt", "rb") as file:
                encrypted_data = file.read()
                # Decrypt the content using the private key
                cipher = PKCS1_OAEP.new(self.private_key)
                
                # Decrypt data in chunks
                decrypted_data = b""
                chunk_size = 256  # RSA block size for 2048-bit key
                for i in range(0, len(encrypted_data), chunk_size):
                    chunk = encrypted_data[i:i+chunk_size]
                    decrypted_data += cipher.decrypt(chunk)
                
                # Deserialize the JSON content
                self.user_db = json.loads(decrypted_data.decode('utf-8'))
        except FileNotFoundError:
            print("No existing database found, starting with an empty user database.")
            self.user_db = {}

    def save_to_file(self):
        """ Save the user data to an encrypted file """
        data_to_encrypt = json.dumps(self.user_db).encode('utf-8')
        # Encrypt and save logic...
        cipher = PKCS1_OAEP.new(self.public_key)
        encrypted_data = b""
        chunk_size = 214  # RSA block size limit for 2048-bit key
        for i in range(0, len(data_to_encrypt), chunk_size):
            chunk = data_to_encrypt[i:i+chunk_size]
            encrypted_data += cipher.encrypt(chunk)

        with open("database.txt", "wb") as file:
            file.write(encrypted_data)

    def register_user(self, username, password):
        """ Register a new user and store only the last OTP token (Sn) """
        hashed_password = self.generate_otp_chain(password, 1)
        otp_chain = self.generate_otp_chain(hashed_password, 100)
        self.user_db[username] = {
            "password": hashed_password,
            "otp_token": otp_chain,  
            "counter": 0  # Start counter from 0
        }
        self.save_to_file()

    def generate_otp_chain(self, password, iterations):
        """ Generate an OTP chain by hashing the password multiple times """
        current_value = password
        for _ in range(iterations):
            sha = SHA256.new()
            sha.update(current_value.encode('utf-8'))
            current_value = sha.hexdigest()
        return current_value
    
    def validate_login(self, username, password):
        """ Validate user credentials during login """
        if username in self.user_db:
            stored_hashed_password = self.user_db[username]['password']
            if self.generate_otp_chain(password, 1) == stored_hashed_password:
                counter = self.user_db[username]['counter']
                return True, counter
        return False, None
    
    def validate_otp(self, username, otp_token):
        """ Validate OTP token and update the OTP chain and counter """
        if username in self.user_db:
            otp_chain = self.generate_otp_chain(otp_token, 1)
            # Validate if OTP token from client matches Sn-1 (client should send Sn-1)
            if otp_chain == self.user_db[username]["otp_token"]:
                self.user_db[username]['otp_token'] = otp_token  # Store the previous token
                self.user_db[username]['counter'] += 1  # Increment counter after successful validation
                self.save_to_file()
                return True
            else:
                 print("OTP does not match computed value.")  # Debugging log
        return False

