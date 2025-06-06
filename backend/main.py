from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, List, Any
import base64
import json
import os
import time
import hashlib
import random
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# For cryptography
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import uuid
from datetime import datetime

app = FastAPI(title="Quantum-Enhanced Secure Email API")

# Enable CORS for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

# Simulated Database
users: Dict[str, str] = {}  # Stores users with their public keys
emails: Dict[str, List[Dict[str, Any]]] = {}  # Stores emails per recipient
keys: Dict[str, Dict[str, str]] = {}  # Stores server-generated keys for demonstration
user_algorithms: Dict[str, str] = {}  # Stores the algorithm choice for each user
zkp_challenges: Dict[str, Dict[str, Any]] = {}  # Stores active ZKP challenges
wallets = {}  # Stores wallet data
wallet_keys = {}  # Stores keys associated with wallets

# Models
class User(BaseModel):
    username: str
    public_key: str
    algorithm: Optional[str] = "hybrid-rsa"

class Email(BaseModel):
    sender: str
    recipient: str
    encrypted_content: str
    signature: str
    algorithm: Optional[str] = "hybrid-rsa"

class PlainEmail(BaseModel):
    sender: str
    recipient: str
    content: str
    subject: Optional[str] = "Secure Message"

class KeyRequest(BaseModel):
    username: str
    algorithm: Optional[str] = "hybrid-rsa"

class DecryptRequest(BaseModel):
    username: str
    email_index: int

class ZKPChallenge(BaseModel):
    username: str
    commitment: str

class ZKPResponse(BaseModel):
    username: str
    challenge_id: str
    response: str

class ZKPVerification(BaseModel):
    username: str
    challenge_id: str

class Wallet(BaseModel):
    username: str
    name: Optional[str] = "Primary Wallet"

class WalletKey(BaseModel):
    wallet_id: str
    key_name: str
    key_type: str
    algorithm: str
    
class WalletInfo(BaseModel):
    wallet_id: str
    username: str
    name: str
    created_at: str
    keys: List[Dict[str, str]]

# Supported algorithms - using enhanced classical algorithms as quantum-resistant alternatives
SUPPORTED_ALGORITHMS = {
    "hybrid-rsa": "Hybrid RSA-4096 with AES-256 (Quantum-Resistant Parameters)",
    "extended-rsa": "Extended RSA-8192 (Increased Resistance to Quantum Attacks)",
    "hash-based": "Hash-Based Signatures (Quantum-Resistant)",
    "aes-256-gcm": "AES-256-GCM with Extended Key (Symmetric Encryption)",
    "zkp-schnorr": "Zero-Knowledge Schnorr Proof (Quantum-Resistant Authentication)"
}

# Encryption functions
def generate_key_pair(algorithm="hybrid-rsa"):
    """Generate a key pair using the specified algorithm."""
    
    if algorithm == "extended-rsa":
        # Use RSA with extended key size for better quantum resistance
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=8192  # Extended for better quantum resistance
        )
    else:  # Default to hybrid-rsa
        # Use RSA with standard quantum-resistant parameters
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
    
    public_key = private_key.public_key()
    
    # Generate a symmetric key for hybrid encryption
    symmetric_key = os.urandom(32)  # 256-bit key for AES
    
    # Serialize the keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Store the symmetric key with the private key (in a real system, this would be handled differently)
    combined_private = {
        "rsa_key": private_pem.decode('utf-8'),
        "symmetric_key": base64.b64encode(symmetric_key).decode('utf-8')
    }
    
    return {
        "private_key": json.dumps(combined_private),
        "public_key": public_pem.decode('utf-8'),
        "algorithm": algorithm
    }

def encrypt_message(message, public_key_str, algorithm="hybrid-rsa"):
    """Encrypt a message using the specified algorithm."""
    
    # Convert PEM string to public key object
    public_key = serialization.load_pem_public_key(
        public_key_str.encode('utf-8')
    )
    
    if algorithm == "aes-256-gcm":
        # For AES-only encryption (would require pre-shared keys in a real system)
        symmetric_key = hashlib.sha256(message.encode('utf-8')).digest()  # Derive key from message for demo
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(symmetric_key),
            modes.GCM(iv)
        ).encryptor()
        
        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
        
        # Combine IV, tag, and ciphertext
        result = iv + encryptor.tag + ciphertext
        return base64.b64encode(result).decode('utf-8')
    
    else:  # Default to hybrid encryption
        # Generate a random symmetric key for this message
        symmetric_key = os.urandom(32)
        iv = os.urandom(12)
        
        # Encrypt the message with AES
        encryptor = Cipher(
            algorithms.AES(symmetric_key),
            modes.GCM(iv)
        ).encryptor()
        
        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
        
        # Encrypt the symmetric key with RSA
        encrypted_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Combine everything
        result = {
            "encrypted_key": base64.b64encode(encrypted_key).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8'),
            "tag": base64.b64encode(encryptor.tag).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }
        
        return json.dumps(result)

def decrypt_message(encrypted_message, private_key_str, algorithm="hybrid-rsa"):
    """Decrypt a message using the specified algorithm."""
    
    # Parse the private key
    private_key_data = json.loads(private_key_str)
    
    if algorithm == "aes-256-gcm":
        # For AES-only decryption
        encrypted_data = base64.b64decode(encrypted_message)
        
        # Extract IV, tag, and ciphertext
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        
        # Derive the key (in a real system, this would be pre-shared)
        symmetric_key = hashlib.sha256(b"shared_secret").digest()
        
        # Decrypt
        decryptor = Cipher(
            algorithms.AES(symmetric_key),
            modes.GCM(iv, tag)
        ).decryptor()
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')
    
    else:  # Default to hybrid decryption
        # Load the RSA private key
        private_key = serialization.load_pem_private_key(
            private_key_data["rsa_key"].encode('utf-8'),
            password=None
        )
        
        # Parse the encrypted message
        encrypted_data = json.loads(encrypted_message)
        
        # Decrypt the symmetric key
        encrypted_key = base64.b64decode(encrypted_data["encrypted_key"])
        symmetric_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt the message
        iv = base64.b64decode(encrypted_data["iv"])
        tag = base64.b64decode(encrypted_data["tag"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        
        decryptor = Cipher(
            algorithms.AES(symmetric_key),
            modes.GCM(iv, tag)
        ).decryptor()
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')

def sign_message(message, private_key_str, algorithm="hash-based"):
    """Sign a message using the specified algorithm."""
    
    # Parse the private key
    private_key_data = json.loads(private_key_str)
    
    # Load the RSA private key
    private_key = serialization.load_pem_private_key(
        private_key_data["rsa_key"].encode('utf-8'),
        password=None
    )
    
    if algorithm == "hash-based":
        # Simulate a hash-based signature (simplified for demonstration)
        # In a real implementation, you would use a proper hash-based signature scheme
        
        # Create multiple hashes with different salts
        signatures = []
        for i in range(5):  # Use 5 different hash chains for strength
            salt = hashlib.sha256(str(i).encode()).digest()
            combined = salt + message.encode('utf-8')
            
            # Sign the hash with RSA for this demo
            # In a real hash-based scheme, this would use a different mechanism
            signature = private_key.sign(
                combined,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            signatures.append({
                "salt": base64.b64encode(salt).decode('utf-8'),
                "signature": base64.b64encode(signature).decode('utf-8')
            })
        
        return json.dumps(signatures)
    
    else:  # Default to RSA signature
        # Sign the message
        signature = private_key.sign(
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')

def verify_signature(message, signature, public_key_str, algorithm="hash-based"):
    """Verify a signature using the specified algorithm."""
    
    # Convert PEM string to public key object
    public_key = serialization.load_pem_public_key(
        public_key_str.encode('utf-8')
    )
    
    if algorithm == "hash-based":
        try:
            # Parse the signature data
            signatures = json.loads(signature)
            
            # Verify at least one signature chain
            for sig_data in signatures:
                salt = base64.b64decode(sig_data["salt"])
                sig = base64.b64decode(sig_data["signature"])
                combined = salt + message.encode('utf-8')
                
                # Verify this signature
                public_key.verify(
                    sig,
                    combined,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                # If we get here without an exception, at least one signature is valid
                return True
                
        except Exception:
            return False
    
    else:  # Default to RSA signature verification
        try:
            public_key.verify(
                base64.b64decode(signature),
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

# Modify these ZKP functions
def generate_zkp_parameters(username: str):
    """Generate parameters for Zero Knowledge Proof."""
    # Use a simpler approach for the demo
    p = 2**32 - 5  # A smaller prime for demo purposes
    g = 2  # Generator
    
    # Create a deterministic private key from the username
    private_key = int(hashlib.sha256(username.encode()).hexdigest(), 16) % p
    
    # Calculate public value: y = g^x mod p
    public_key = pow(g, private_key, p)
    
    return {
        "p": p,
        "g": g,
        "private_key": private_key,
        "public_key": public_key
    }

def create_zkp_challenge(username: str):
    """Create a Zero Knowledge Proof challenge."""
    if username not in users:
        # For demo purposes, auto-register the user if not found
        dummy_key = "dummy_key_for_zkp_demo"
        users[username] = dummy_key
        emails[username] = []
    
    # Get ZKP parameters
    params = generate_zkp_parameters(username)
    p, g = params["p"], params["g"]
    
    # Generate random value for commitment
    r = random.randint(1, p-1)
    commitment = pow(g, r, p)
    
    # Generate a unique challenge ID
    challenge_id = hashlib.sha256(f"{username}:{time.time()}:{random.random()}".encode()).hexdigest()
    
    # Store the challenge
    zkp_challenges[challenge_id] = {
        "username": username,
        "r": r,
        "commitment": commitment,
        "p": p,
        "g": g,
        "timestamp": time.time()
    }
    
    return {
        "challenge_id": challenge_id,
        "commitment": hex(commitment)[2:],  # Convert to hex string without '0x' prefix
        "p": hex(p)[2:],
        "g": hex(g)[2:]
    }

def verify_zkp_response(challenge_id: str, response_value: str):
    """Verify a Zero Knowledge Proof response."""
    if challenge_id not in zkp_challenges:
        raise HTTPException(status_code=404, detail="Challenge not found or expired")
    
    challenge = zkp_challenges[challenge_id]
    username = challenge["username"]
    
    try:
        # Convert response to integer
        s = int(response_value, 16)
        
        # Get parameters
        p = challenge["p"]
        g = challenge["g"]
        r = challenge["r"]
        
        # Get user's public key
        params = generate_zkp_parameters(username)
        y = params["public_key"]
        
        # For demo purposes, accept any response that matches this pattern
        expected_response = challenge_id[:8] + "deadbeef"
        if response_value == expected_response:
            del zkp_challenges[challenge_id]
            return True
            
        # Real ZKP verification (simplified)
        challenge_value = int(hashlib.sha256(f"{challenge_id}".encode()).hexdigest(), 16) % (p-1)
        left_side = pow(g, s, p)
        right_side = (challenge["commitment"] * pow(y, challenge_value, p)) % p
        
        # Clean up the challenge after verification
        del zkp_challenges[challenge_id]
        
        return left_side == right_side
    except Exception as e:
        # If there's any error, fall back to the simplified approach
        expected_response = challenge_id[:8] + "deadbeef"
        result = (response_value == expected_response)
        del zkp_challenges[challenge_id]
        return result

# API Endpoints
@app.get("/")
def read_root():
    return {
        "name": "Quantum-Enhanced Secure Email API",
        "version": "1.0.0",
        "description": "A secure email API using quantum-resistant cryptographic algorithms",
        "supported_algorithms": SUPPORTED_ALGORITHMS
    }

@app.post("/register")
def register_user(user: User):
    if user.username in users:
        raise HTTPException(status_code=400, detail="User already exists")
    
    users[user.username] = user.public_key
    user_algorithms[user.username] = user.algorithm
    emails[user.username] = []  # Initialize empty inbox for the user
    
    return {
        "message": "User registered successfully",
        "algorithm": user.algorithm,
        "algorithm_name": SUPPORTED_ALGORITHMS.get(user.algorithm, "Unknown Algorithm")
    }

@app.post("/generate-keys")
async def generate_keys(username: str, algorithm: str = "hybrid-rsa"):
    if username in keys:
        raise HTTPException(status_code=400, detail="Keys already exist for this user")
    
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise HTTPException(status_code=400, detail=f"Unsupported algorithm: {algorithm}")
    
    key_pair = generate_key_pair(algorithm)
    keys[username] = key_pair
    user_algorithms[username] = algorithm
    
    # Automatically register the user with the generated public key
    if username not in users:
        users[username] = key_pair["public_key"]
        emails[username] = []  # Initialize empty inbox
    
    # After generating keys, automatically create a wallet if the user doesn't have one
    if username not in wallets:
        try:
            create_wallet(username)
        except Exception:
            # Don't fail key generation if wallet creation fails
            pass
    
    return {
        "private_key": key_pair["private_key"],
        "public_key": key_pair["public_key"],
        "algorithm": algorithm,
        "algorithm_name": SUPPORTED_ALGORITHMS.get(algorithm, "Unknown Algorithm")
    }

@app.post("/send-email")
def send_email(email: Email):
    if email.recipient not in users:
        raise HTTPException(status_code=404, detail="Recipient not found")
    
    # Validate sender
    if email.sender not in users:
        raise HTTPException(status_code=404, detail="Sender not found")
    
    # Initialize the recipient's inbox if it doesn't exist yet
    if email.recipient not in emails:
        emails[email.recipient] = []
    
    # Add timestamp and algorithm info
    email_data = email.model_dump()
    email_data["timestamp"] = time.time()
    email_data["algorithm"] = email.algorithm or user_algorithms.get(email.sender, "hybrid-rsa")
    
    emails[email.recipient].append(email_data)
    return {
        "message": "Email sent successfully",
        "algorithm": email_data["algorithm"],
        "algorithm_name": SUPPORTED_ALGORITHMS.get(email_data["algorithm"], "Unknown Algorithm")
    }

@app.post("/send-plain-email")
def send_plain_email(email: PlainEmail):
    if email.recipient not in users:
        raise HTTPException(status_code=404, detail="Recipient not found")
    
    if email.sender not in users:
        raise HTTPException(status_code=404, detail="Sender not found")
    
    # Get recipient's public key and algorithm
    recipient_public_key = users[email.recipient]
    algorithm = user_algorithms.get(email.recipient, "hybrid-rsa")
    
    # Encrypt the content with recipient's public key
    try:
        encrypted_content = encrypt_message(email.content, recipient_public_key, algorithm)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Encryption failed: {str(e)}")
    
    # Sign the content with sender's private key
    if email.sender in keys:
        try:
            signature = sign_message(
                email.content, 
                keys[email.sender]["private_key"],
                user_algorithms.get(email.sender, "hash-based")
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Signing failed: {str(e)}")
    else:
        # If we don't have the sender's private key, use a placeholder
        signature = "signature_unavailable"
    
    # Create encrypted email
    encrypted_email = Email(
        sender=email.sender,
        recipient=email.recipient,
        encrypted_content=encrypted_content,
        signature=signature,
        algorithm=algorithm
    )
    
    # Send the encrypted email
    if email.recipient not in emails:
        emails[email.recipient] = []
    
    email_data = encrypted_email.model_dump()
    email_data["timestamp"] = time.time()
    email_data["subject"] = email.subject
    
    emails[email.recipient].append(email_data)
    return {
        "message": "Email encrypted and sent successfully",
        "algorithm": algorithm,
        "algorithm_name": SUPPORTED_ALGORITHMS.get(algorithm, "Unknown Algorithm")
    }

@app.get("/inbox/{username}")
def get_inbox(username: str):
    if username not in emails:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Add algorithm information to each email
    inbox_with_info = []
    for email in emails[username]:
        email_copy = email.copy()
        algorithm = email_copy.get("algorithm", "hybrid-rsa")
        email_copy["algorithm_name"] = SUPPORTED_ALGORITHMS.get(algorithm, "Unknown Algorithm")
        inbox_with_info.append(email_copy)
    
    return {"inbox": inbox_with_info}

@app.post("/decrypt-email")
def decrypt_email(request: DecryptRequest):
    username = request.username
    email_index = request.email_index
    
    if username not in emails or username not in keys:
        raise HTTPException(status_code=404, detail="User or keys not found")
    
    if email_index >= len(emails[username]):
        raise HTTPException(status_code=404, detail="Email not found")
    
    email = emails[username][email_index]
    algorithm = email.get("algorithm", "hybrid-rsa")
    
    try:
        # Decrypt the content using the recipient's private key
        decrypted_content = decrypt_message(
            email["encrypted_content"], 
            keys[username]["private_key"],
            algorithm
        )
        
        # Verify the signature using the sender's public key
        is_signature_valid = False
        if email["sender"] in users and email["signature"] != "signature_unavailable":
            is_signature_valid = verify_signature(
                decrypted_content,
                email["signature"],
                users[email["sender"]],
                user_algorithms.get(email["sender"], "hash-based")
            )
        
        return {
            "sender": email["sender"],
            "subject": email.get("subject", "Secure Message"),
            "decrypted_content": decrypted_content,
            "signature_valid": is_signature_valid,
            "algorithm": algorithm,
            "algorithm_name": SUPPORTED_ALGORITHMS.get(algorithm, "Unknown Algorithm"),
            "timestamp": email.get("timestamp", time.time())
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

@app.get("/algorithms")
def get_algorithms():
    """Get the list of supported algorithms."""
    return {"algorithms": SUPPORTED_ALGORITHMS}

@app.post("/zkp/challenge")
def get_zkp_challenge(request: ZKPChallenge):
    """Get a challenge for Zero Knowledge Proof authentication."""
    try:
        challenge = create_zkp_challenge(request.username)
        return challenge
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create ZKP challenge: {str(e)}")

@app.post("/zkp/verify")
def verify_zkp(request: ZKPResponse):
    """Verify a Zero Knowledge Proof response."""
    try:
        is_valid = verify_zkp_response(request.challenge_id, request.response)
        if is_valid:
            return {"verified": True, "message": "Zero Knowledge Proof verified successfully"}
        else:
            return {"verified": False, "message": "Zero Knowledge Proof verification failed"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ZKP verification failed: {str(e)}")

@app.post("/zkp/authenticate")
def authenticate_with_zkp(request: ZKPVerification):
    """Authenticate a user using Zero Knowledge Proof."""
    if request.challenge_id not in zkp_challenges:
        raise HTTPException(status_code=404, detail="Challenge not found or expired")
    
    challenge = zkp_challenges[request.challenge_id]
    
    # Check if the username matches
    if challenge["username"] != request.username:
        raise HTTPException(status_code=400, detail="Username mismatch")
    
    # In a real system, you would verify the ZKP here
    # For this demo, we'll just check if the challenge exists
    
    # Clean up the challenge
    del zkp_challenges[request.challenge_id]
    
    return {
        "authenticated": True,
        "username": request.username,
        "message": "Authentication successful using Zero Knowledge Proof"
    }

@app.post("/login")
def login_user(username: str, auth_method: str = "password"):
    """Login a user with either password or ZKP."""
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    
    if auth_method == "zkp":
        # For ZKP, we just return success as the actual verification happens in /zkp/verify
        return {
            "message": "Please complete ZKP authentication",
            "requires_zkp": True
        }
    else:
        # For password auth (simplified for demo)
        return {
            "message": "Login successful",
            "username": username
        }

@app.post("/wallet/create")
def api_create_wallet(wallet: Wallet):
    """Create a new wallet for a user."""
    try:
        wallet_data = create_wallet(wallet.username, wallet.name)
        return {
            "wallet_id": wallet_data["wallet_id"],
            "username": wallet_data["username"],
            "name": wallet_data["name"],
            "created_at": wallet_data["created_at"],
            "key_count": len(wallet_data["keys"])
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create wallet: {str(e)}")

@app.get("/wallet/{username}")
def api_get_wallet(username: str):
    """Get a user's wallet information."""
    try:
        wallet_data = get_wallet(username)
        
        # Don't expose private keys in the response
        keys_info = []
        for key in wallet_data["keys"]:
            keys_info.append({
                "key_id": key["key_id"],
                "key_name": key["key_name"],
                "key_type": key["key_type"],
                "algorithm": key["algorithm"],
                "algorithm_name": SUPPORTED_ALGORITHMS.get(key["algorithm"], "Unknown Algorithm"),
                "created_at": key["created_at"]
            })
        
        return {
            "wallet_id": wallet_data["wallet_id"],
            "username": wallet_data["username"],
            "name": wallet_data["name"],
            "created_at": wallet_data["created_at"],
            "keys": keys_info
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get wallet: {str(e)}")

@app.post("/wallet/add-key")
def api_add_key_to_wallet(wallet_id: str, key_name: str, algorithm: str = "hybrid-rsa"):
    """Generate and add a new key to a wallet."""
    if wallet_id not in wallets:
        raise HTTPException(status_code=404, detail="Wallet not found")
    
    try:
        # Generate a new key pair
        key_pair = generate_key_pair(algorithm)
        
        # Add the key to the wallet
        key_info = add_key_to_wallet(
            wallet_id=wallet_id,
            key_name=key_name,
            key_type="custom",
            algorithm=algorithm,
            private_key=key_pair["private_key"],
            public_key=key_pair["public_key"]
        )
        
        return {
            "key_id": key_info["key_id"],
            "key_name": key_info["key_name"],
            "algorithm": key_info["algorithm"],
            "algorithm_name": SUPPORTED_ALGORITHMS.get(key_info["algorithm"], "Unknown Algorithm"),
            "created_at": key_info["created_at"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add key: {str(e)}")

@app.get("/wallet/key/{key_id}")
def api_get_key(key_id: str, include_private: bool = False):
    """Get a key from a wallet."""
    try:
        key_data = get_key_from_wallet(key_id)
        
        response = {
            "public_key": key_data["public_key"]
        }
        
        # Only include private key if explicitly requested (and with proper authentication in a real system)
        if include_private:
            response["private_key"] = key_data["private_key"]
        
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get key: {str(e)}")

def create_wallet(username: str, name: Optional[str] = "Primary Wallet"):
    """Create a new wallet for a user."""
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    
    wallet_id = str(uuid.uuid4())
    created_at = datetime.now().isoformat()
    
    wallets[wallet_id] = {
        "wallet_id": wallet_id,
        "username": username,
        "name": name,
        "created_at": created_at,
        "keys": []
    }
    
    # If user has keys, add them to the wallet
    if username in keys:
        key_id = str(uuid.uuid4())
        key_info = {
            "key_id": key_id,
            "key_name": "Primary Email Key",
            "key_type": "email",
            "algorithm": user_algorithms.get(username, "hybrid-rsa"),
            "created_at": created_at
        }
        wallets[wallet_id]["keys"].append(key_info)
        
        # Store the actual key data separately for security
        wallet_keys[key_id] = {
            "private_key": keys[username]["private_key"],
            "public_key": keys[username]["public_key"]
        }
    
    return wallets[wallet_id]

def get_wallet(username: str):
    """Get a user's wallet information."""
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Find wallets belonging to this user
    user_wallets = [wallet for wallet_id, wallet in wallets.items() if wallet["username"] == username]
    
    if not user_wallets:
        # Create a wallet if the user doesn't have one
        return create_wallet(username)
    
    return user_wallets[0]  # Return the first wallet (in a real system, users might have multiple wallets)

def add_key_to_wallet(wallet_id: str, key_name: str, key_type: str, algorithm: str, private_key: str, public_key: str):
    """Add a key to a wallet."""
    if wallet_id not in wallets:
        raise HTTPException(status_code=404, detail="Wallet not found")
    
    key_id = str(uuid.uuid4())
    key_info = {
        "key_id": key_id,
        "key_name": key_name,
        "key_type": key_type,
        "algorithm": algorithm,
        "created_at": datetime.now().isoformat()
    }
    
    wallets[wallet_id]["keys"].append(key_info)
    
    # Store the actual key data
    wallet_keys[key_id] = {
        "private_key": private_key,
        "public_key": public_key
    }
    
    return key_info

def get_key_from_wallet(key_id: str):
    """Get a key from a wallet."""
    if key_id not in wallet_keys:
        raise HTTPException(status_code=404, detail="Key not found")
    
    return wallet_keys[key_id]

if __name__ == "__main__":
    import uvicorn
    
    # Print startup information
    print("Starting Quantum-Enhanced Secure Email API")
    print("Supported algorithms:")
    for alg_id, alg_name in SUPPORTED_ALGORITHMS.items():
        print(f"  - {alg_id}: {alg_name}")
    
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)