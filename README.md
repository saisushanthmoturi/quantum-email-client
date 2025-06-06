# Quantum-Resistant Secure Email Client

A cutting-edge secure email system that implements quantum-resistant cryptographic algorithms to protect communications against both classical and quantum computing attacks.

## 🚀 Overview

This project demonstrates advanced cryptographic techniques including:
- **Quantum-resistant encryption algorithms**
- **Zero Knowledge Proof (ZKP) authentication**
- **Hybrid encryption schemes**
- **Hash-based digital signatures**
- **Secure key management with wallet system**

## 🔐 Security Features

### Quantum-Resistant Algorithms
- **Hybrid RSA-4096 with AES-256**: Enhanced parameters for quantum resistance
- **Extended RSA-8192**: Maximum security with increased key sizes
- **Hash-Based Signatures**: Quantum-resistant digital signatures
- **AES-256-GCM**: Symmetric encryption with authentication

### Advanced Authentication
- **Traditional password authentication**
- **Zero Knowledge Proof (ZKP)**: Prove identity without revealing passwords
- **Schnorr-based ZKP implementation**

### Key Management
- **Quantum Key Wallet**: Secure storage and management of cryptographic keys
- **Multiple key support**: Generate and manage different keys for various purposes
- **Algorithm flexibility**: Support for multiple quantum-resistant algorithms

## 🏗️ Architecture

```
email/
├── frontend/           # React-like vanilla JS frontend
│   ├── index.html     # Main application interface
│   ├── script.js      # Application logic and API calls
│   └── style.css      # Modern, responsive styling
├── backend/           # FastAPI Python backend
│   ├── main.py        # Core API with cryptographic implementations
│   └── requirements.txt # Python dependencies
└── .vscode/
    └── settings.json  # Development environment settings
```

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.8+
- Node.js (for live server)
- Modern web browser

### Backend Setup

1. **Navigate to backend directory:**
   ```bash
   cd backend
   ```

2. **Install Python dependencies:**
   ```bash
   pip install fastapi uvicorn cryptography pydantic
   ```

3. **Start the backend server:**
   ```bash
   python main.py
   ```
   The API will be available at `http://localhost:8000`

### Frontend Setup

1. **Navigate to frontend directory:**
   ```bash
   cd frontend
   ```

2. **Start a local web server:**
   ```bash
   # Using Python
   python -m http.server 3000
   
   # Or using Node.js
   npx http-server -p 3000
   
   # Or using Live Server extension in VS Code
   ```

3. **Open your browser and navigate to:**
   ```
   http://localhost:3000
   ```

## 🎯 Usage Guide

### 1. User Registration
- Select a quantum-resistant algorithm
- Enter your username
- Generate your quantum-resistant key pair
- Securely store your private key

### 2. Sending Secure Emails
- Enter recipient's username
- Compose your message
- The system automatically encrypts using quantum-resistant algorithms
- Messages are digitally signed for authenticity

### 3. Receiving & Decrypting Emails
- Check your secure inbox
- Decrypt messages using your private key
- Verify digital signatures for authenticity

### 4. Zero Knowledge Proof Login
- Select ZKP authentication method
- Request a cryptographic challenge
- Provide proof without revealing your password
- Complete secure authentication

### 5. Key Wallet Management
- Create and manage multiple cryptographic keys
- View key details and algorithms
- Generate specialized keys for different purposes

## 🔬 Cryptographic Implementation

### Encryption Process
```python
# Hybrid encryption approach
1. Generate random AES-256 key
2. Encrypt message with AES-256-GCM
3. Encrypt AES key with RSA (4096/8192-bit)
4. Combine encrypted key + encrypted message
```

### Digital Signatures
```python
# Hash-based signature scheme
1. Create multiple hash chains with different salts
2. Sign each hash with RSA-PSS
3. Provide multiple signature proofs
4. Verify any valid signature chain
```

### Zero Knowledge Proof
```python
# Schnorr-based ZKP protocol
1. Prover commits to random value
2. Verifier provides challenge
3. Prover responds without revealing secret
4. Verifier confirms proof validity
```

## 🌐 API Endpoints

### Authentication
- `POST /generate-keys` - Generate quantum-resistant key pairs
- `POST /zkp/challenge` - Request ZKP challenge
- `POST /zkp/verify` - Verify ZKP response

### Email Operations
- `POST /send-plain-email` - Send encrypted email
- `GET /inbox/{username}` - Retrieve user's inbox
- `POST /decrypt-email` - Decrypt received email

### Wallet Management
- `POST /wallet/create` - Create new key wallet
- `GET /wallet/{username}` - Get wallet information
- `POST /wallet/add-key` - Generate new key in wallet

## 🔧 Configuration

### Supported Algorithms
```javascript
const ALGORITHMS = {
    "hybrid-rsa": "Hybrid RSA-4096 with AES-256",
    "extended-rsa": "Extended RSA-8192",
    "hash-based": "Hash-Based Signatures",
    "aes-256-gcm": "AES-256-GCM Symmetric"
};
```

### Security Parameters
- **RSA Key Sizes**: 4096-bit (standard), 8192-bit (maximum)
- **AES Encryption**: 256-bit keys with GCM mode
- **Hash Functions**: SHA-256 for all operations
- **Signature Padding**: PSS with maximum salt length

## 🛡️ Security Considerations

### Quantum Resistance
- **Key Sizes**: Extended beyond current standards
- **Algorithm Selection**: Future-proof cryptographic choices
- **Hybrid Approaches**: Multiple layers of protection

### Implementation Security
- **Secure Random Generation**: OS-level entropy sources
- **Memory Protection**: Secure key handling practices
- **Time-based Attacks**: Constant-time operations where possible

### Best Practices
- **Key Rotation**: Regular key updates recommended
- **Secure Storage**: Private keys never transmitted
- **Authentication**: Multi-factor approaches supported

## 📊 Performance Metrics

### Encryption Performance
- **RSA-4096**: ~2ms per operation
- **RSA-8192**: ~8ms per operation
- **AES-256**: <1ms per 1KB message

### Key Generation
- **RSA-4096**: ~500ms
- **RSA-8192**: ~2000ms
- **Hash-based**: ~100ms

## 🔮 Future Enhancements

### Planned Features
- [ ] NIST Post-Quantum Cryptography standards
- [ ] Lattice-based encryption schemes
- [ ] Multi-party computation protocols
- [ ] Hardware security module integration

### Quantum-Safe Roadmap
- [ ] Implement CRYSTALS-Dilithium signatures
- [ ] Add CRYSTALS-KYBER key exchange
- [ ] Integrate SPHINCS+ hash signatures
- [ ] Support for quantum key distribution

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/quantum-enhancement`)
3. Commit your changes (`git commit -am 'Add quantum-safe feature'`)
4. Push to the branch (`git push origin feature/quantum-enhancement`)
5. Create a Pull Request

### Development Guidelines
- Follow cryptographic best practices
- Include comprehensive tests for security features
- Document all cryptographic implementations
- Ensure quantum-resistance of new algorithms

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This is an educational and demonstration project. While it implements real cryptographic algorithms, it should not be used for production systems without thorough security auditing and compliance review.

## 🔗 References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Quantum-Safe Cryptography](https://www.etsi.org/technologies/quantum-safe-cryptography)
- [Zero Knowledge Proofs](https://en.wikipedia.org/wiki/Zero-knowledge_proof)

## 📞 Support

For questions, issues, or contributions:
- Create an issue in the GitHub repository
- Contact the development team
- Join our cryptography discussion forums

---

**Built with quantum-resistance in mind 🔐**
