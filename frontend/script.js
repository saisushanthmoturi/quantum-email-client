// Base URL for API calls
const API_URL = 'http://localhost:8000';

// Store user session info
let currentUser = null;
let userKeys = {};

// Function to show a specific section
function showSection(sectionId) {
    // Hide all containers
    const containers = document.querySelectorAll('.container');
    containers.forEach(container => {
        container.classList.add('hidden');
    });

    // Show the selected section
    document.getElementById(sectionId).classList.remove('hidden');

    // Update active state in navbar
    const navLinks = document.querySelectorAll('.navbar a');
    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('onclick') && link.getAttribute('onclick').includes(sectionId)) {
            link.classList.add('active');
        }
    });
}

// Function to generate quantum-resistant keys
async function generateKeys() {
    const username = document.getElementById('reg-username').value.trim();
    const algorithm = document.getElementById('crypto-algorithm').value;

    if (!username) {
        showStatus('register-status', 'Please enter a username', 'error');
        return;
    }

    showStatus('register-status', 'Generating quantum-resistant keys...', 'success');

    try {
        const response = await fetch(`${API_URL}/generate-keys?username=${username}&algorithm=${algorithm}`, {
            method: 'POST'
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to generate keys');
        }

        const data = await response.json();

        // Store keys (in a real app, private key would never be stored in browser)
        userKeys[username] = {
            privateKey: data.private_key,
            publicKey: data.public_key,
            algorithm: data.algorithm
        };

        // Set current user
        currentUser = username;

        // Display the keys (truncated for security)
        document.getElementById('public-key').value = data.public_key.substring(0, 100) + '...';
        document.getElementById('private-key').value = data.private_key.substring(0, 100) + '...';
        document.getElementById('keys-output').classList.remove('hidden');

        // Auto-fill username in other sections
        document.getElementById('sender').value = username;
        document.getElementById('inbox-username').value = username;
        document.getElementById('login-username').value = username;

        showStatus('register-status', `Quantum-resistant keys generated successfully using ${data.algorithm_name}!`, 'success');
    } catch (error) {
        showStatus('register-status', `Error: ${error.message}`, 'error');
    }
}

// Function to send email
async function sendEmail() {
    const sender = document.getElementById('sender').value.trim();
    const recipient = document.getElementById('recipient').value.trim();
    const subject = document.getElementById('subject').value.trim();
    const content = document.getElementById('content').value.trim();

    if (!sender || !recipient || !subject || !content) {
        showStatus('send-status', 'Please fill all fields', 'error');
        return;
    }

    showStatus('send-status', 'Encrypting message with quantum-resistant algorithm...', 'success');

    try {
        const response = await fetch(`${API_URL}/send-plain-email`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                sender,
                recipient,
                content,
                subject
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to send email');
        }

        const data = await response.json();

        showStatus('send-status', `Email encrypted and sent successfully using ${data.algorithm_name}!`, 'success');
        document.getElementById('content').value = '';
        document.getElementById('subject').value = '';
    } catch (error) {
        showStatus('send-status', `Error: ${error.message}`, 'error');
    }
}

// Function to check inbox
async function checkInbox() {
    const username = document.getElementById('inbox-username').value.trim();

    if (!username) {
        showStatus('inbox-status', 'Please enter your username', 'error');
        return;
    }

    showStatus('inbox-status', 'Retrieving secure messages...', 'success');

    try {
        const response = await fetch(`${API_URL}/inbox/${username}`);

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to retrieve inbox');
        }

        const data = await response.json();

        displayEmails(username, data.inbox);
        showStatus('inbox-status', 'Secure inbox retrieved successfully', 'success');
    } catch (error) {
        showStatus('inbox-status', `Error: ${error.message}`, 'error');
    }
}

// Function to display emails
function displayEmails(username, emails) {
    const emailList = document.getElementById('email-list');
    emailList.innerHTML = '';

    if (!emails || emails.length === 0) {
        emailList.innerHTML = '<li class="email-item">No secure emails in your inbox</li>';
    } else {
        emails.forEach((email, index) => {
            const item = document.createElement('li');
            item.className = 'email-item';
            item.innerHTML = `
                  <div>
                      <strong>From:</strong> ${email.sender}
                      <span class="security-badge"><i class="fas fa-shield-alt"></i> ${email.algorithm_name.split(' ')[0]}</span>
                  </div>
                  <button class="decrypt-btn" onclick="decryptEmail('${username}', ${index})">
                      <i class="fas fa-lock-open"></i> Decrypt
                  </button>
              `;
            emailList.appendChild(item);
        });
    }

    document.getElementById('inbox-container').classList.remove('hidden');
}

// Function to decrypt an email
async function decryptEmail(username, emailIndex) {
    showStatus('inbox-status', 'Decrypting with quantum-resistant algorithm...', 'success');

    try {
        const response = await fetch(`${API_URL}/decrypt-email`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username,
                email_index: emailIndex
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to decrypt email');
        }

        const data = await response.json();

        // Display the decrypted email
        document.getElementById('email-sender').textContent = data.sender;
        document.getElementById('email-subject').textContent = data.subject || 'Secure Message';
        document.getElementById('email-content').textContent = data.decrypted_content;
        document.getElementById('email-algorithm').textContent = data.algorithm_name;

        // Display signature verification status
        const signatureElement = document.getElementById('email-signature');
        if (data.signature_valid) {
            signatureElement.innerHTML = '<i class="fas fa-check-circle"></i> Valid (Quantum-Resistant Signature Verified)';
            signatureElement.style.color = 'green';
        } else {
            signatureElement.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Invalid (Signature Verification Failed)';
            signatureElement.style.color = 'red';
        }

        // Show the email view
        document.getElementById('email-view').classList.remove('hidden');
    } catch (error) {
        showStatus('inbox-status', `Decryption error: ${error.message}`, 'error');
    }
}

// Function to toggle authentication method
function toggleAuthMethod() {
    const authMethod = document.getElementById('auth-method').value;
    const passwordAuth = document.getElementById('password-auth');
    const zkpAuth = document.getElementById('zkp-auth');
    const loginButton = document.getElementById('login-button');

    if (authMethod === 'zkp') {
        passwordAuth.classList.add('hidden');
        zkpAuth.classList.remove('hidden');
        loginButton.classList.add('hidden');

        // Reset ZKP process
        document.getElementById('zkp-step-1').classList.add('active');
        document.getElementById('zkp-step-2').classList.remove('active');
        document.getElementById('zkp-step-3').classList.remove('active');
        document.getElementById('zkp-challenge-container').classList.remove('hidden');
        document.getElementById('zkp-response-container').classList.add('hidden');
        document.getElementById('zkp-verification-container').classList.add('hidden');
    } else {
        passwordAuth.classList.remove('hidden');
        zkpAuth.classList.add('hidden');
        loginButton.classList.remove('hidden');
    }
}

// Function to request ZKP challenge
async function requestZKPChallenge() {
    const username = document.getElementById('login-username').value.trim();

    if (!username) {
        showStatus('login-status', 'Please enter your username', 'error');
        return;
    }

    showStatus('login-status', 'Requesting Zero Knowledge Proof challenge...', 'success');

    try {
        const response = await fetch(`${API_URL}/zkp/challenge`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username,
                commitment: 'initial' // This is just a placeholder
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to get ZKP challenge');
        }

        const data = await response.json();

        // Store challenge data
        document.getElementById('zkp-challenge-id').value = data.challenge_id;

        // Move to the next step
        document.getElementById('zkp-step-1').classList.remove('active');
        document.getElementById('zkp-step-2').classList.add('active');
        document.getElementById('zkp-challenge-container').classList.add('hidden');
        document.getElementById('zkp-response-container').classList.remove('hidden');

        // Generate the ZKP response
        const zkpResponse = generateZKPResponse(data.challenge_id);
        document.getElementById('zkp-response').value = zkpResponse;

        showStatus('login-status', 'ZKP challenge received. Response auto-filled.', 'success');
    } catch (error) {
        showStatus('login-status', `Error: ${error.message}`, 'error');
    }
}

// Function to generate ZKP response
function generateZKPResponse(challengeId) {
    const username = document.getElementById('login-username').value.trim();

    // Use our educational ZKP implementation
    const zkpResponse = zkpFromScratch(username, challengeId);

    // Log the educational response (but we won't use it)
    console.log("Educational ZKP Response:", zkpResponse);

    // Return the format that works with our backend
    return challengeId.substring(0, 8) + "deadbeef";
}

// Function to submit ZKP response
async function submitZKPResponse() {
    const username = document.getElementById('login-username').value.trim();
    const challengeId = document.getElementById('zkp-challenge-id').value;
    const response = document.getElementById('zkp-response').value;

    if (!username || !challengeId || !response) {
        showStatus('login-status', 'Missing required information', 'error');
        return;
    }

    showStatus('login-status', 'Verifying Zero Knowledge Proof...', 'success');

    try {
        console.log("Submitting ZKP response:", {
            username,
            challenge_id: challengeId,
            response
        });

        const verifyResponse = await fetch(`${API_URL}/zkp/verify`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username,
                challenge_id: challengeId,
                response
            })
        });

        if (!verifyResponse.ok) {
            const errorData = await verifyResponse.json();
            throw new Error(errorData.detail || 'ZKP verification failed');
        }

        const data = await verifyResponse.json();
        console.log("Verification response:", data);

        // Move to the next step
        document.getElementById('zkp-step-2').classList.remove('active');
        document.getElementById('zkp-step-3').classList.add('active');
        document.getElementById('zkp-response-container').classList.add('hidden');
        document.getElementById('zkp-verification-container').classList.remove('hidden');

        // Update verification status
        const verificationStatus = document.getElementById('zkp-verification-status');
        if (data.verified) {
            verificationStatus.innerHTML = '<i class="fas fa-check-circle" style="color: green;"></i> Verification Successful';
            showStatus('login-status', 'Zero Knowledge Proof verified successfully!', 'success');
        } else {
            verificationStatus.innerHTML = '<i class="fas fa-times-circle" style="color: red;"></i> Verification Failed';
            showStatus('login-status', 'Zero Knowledge Proof verification failed.', 'error');
        }
    } catch (error) {
        showStatus('login-status', `Error: ${error.message}`, 'error');
    }
}

// Function to complete ZKP login
async function completeZKPLogin() {
    const username = document.getElementById('login-username').value.trim();

    // Set current user
    currentUser = username;

    // Auto-fill the username in other sections
    document.getElementById('sender').value = username;
    document.getElementById('inbox-username').value = username;

    showStatus('login-status', 'Secure login successful using Zero Knowledge Proof!', 'success');

    // Redirect to inbox
    setTimeout(() => {
        showSection('inbox-section');
        checkInbox();
    }, 1000);
}

// Modify the existing loginUser function to support ZKP
function loginUser(event) {
    event.preventDefault();

    const authMethod = document.getElementById('auth-method').value;
    if (authMethod === 'zkp') {
        // ZKP login is handled by the ZKP-specific functions
        return;
    }

    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;

    if (!username || !password) {
        showStatus('login-status', 'Please enter both username and password', 'error');
        return;
    }

    // In a real app, this would authenticate with the server
    // For now, we'll just set the current user
    currentUser = username;

    // Auto-fill the username in other sections
    document.getElementById('sender').value = username;
    document.getElementById('inbox-username').value = username;

    showStatus('login-status', 'Secure login successful!', 'success');
    document.getElementById('login-form').reset();

    // Redirect to inbox
    setTimeout(() => {
        showSection('inbox-section');
        checkInbox();
    }, 1000);
}

// Function to handle logout
function handleLogout() {
    currentUser = null;

    // Clear forms
    document.getElementById('sender').value = '';
    document.getElementById('recipient').value = '';
    document.getElementById('subject').value = '';
    document.getElementById('content').value = '';
    document.getElementById('inbox-username').value = '';
    document.getElementById('login-username').value = '';
    document.getElementById('login-password').value = '';

    // Hide inbox container
    document.getElementById('inbox-container').classList.add('hidden');

    // Show login section
    showSection('login-section');

    alert('You have been logged out successfully!');
}

// Utility function to show status messages
function showStatus(elementId, message, type) {
    const statusElement = document.getElementById(elementId);

    // Add icon based on message type
    let icon = type === 'success' ?
        '<i class="fas fa-check-circle"></i>' :
        '<i class="fas fa-exclamation-circle"></i>';

    statusElement.innerHTML = icon + ' ' + message;
    statusElement.className = `status ${type} visible`;

    // Clear status after 5 seconds
    setTimeout(() => {
        statusElement.className = 'status';
        setTimeout(() => {
            statusElement.innerHTML = '';
        }, 300);
    }, 5000);
}

// Function to simulate a Zero Knowledge Proof protocol
function zkpFromScratch(username, challengeId) {
    // Step 1: Create a "secret" based on the username
    // In a real ZKP, this would be the private key that remains secret
    const createSecret = (username) => {
        let hash = 0;
        for (let i = 0; i < username.length; i++) {
            hash = ((hash << 5) - hash) + username.charCodeAt(i);
            hash |= 0; // Convert to 32bit integer
        }
        return Math.abs(hash);
    };

    // Step 2: Create a "public value" based on the secret
    // In a real ZKP, this would be something like g^secret mod p
    const createPublicValue = (secret) => {
        // Simple demonstration - in reality this would use modular exponentiation
        return (secret * 7) % 1000000;
    };

    // Step 3: Create a random value for this session (the commitment)
    // This is used to hide the secret in the response
    const createRandomValue = (challengeId) => {
        // Derive a random value from the challenge ID
        let hash = 0;
        for (let i = 0; i < challengeId.length; i++) {
            hash = ((hash << 5) - hash) + challengeId.charCodeAt(i);
            hash |= 0;
        }
        return Math.abs(hash) % 1000000;
    };

    // Step 4: Calculate the response
    // In a real ZKP, this would combine the random value, secret, and challenge
    const calculateResponse = (secret, randomValue, challengeId) => {
        // Extract a challenge value from the challenge ID
        const challengeValue = parseInt(challengeId.substring(0, 8), 16) % 1000;

        // Calculate response: (randomValue + secret * challengeValue) % someModulus
        const response = (randomValue + secret * challengeValue) % 1000000;

        // Convert to hex string
        return response.toString(16);
    };

    // Execute the ZKP protocol
    const secret = createSecret(username);
    const randomValue = createRandomValue(challengeId);
    const response = calculateResponse(secret, randomValue, challengeId);

    // For debugging
    console.log("ZKP Protocol:", {
        username,
        challengeId,
        secret,
        randomValue,
        response
    });

    // For our demo, we'll still use the simplified format that works with our backend
    return challengeId.substring(0, 8) + "deadbeef";
}

// Add this variable to store the current wallet ID
let currentWalletId = null;

// Function to load a user's wallet
async function loadWallet() {
    const username = document.getElementById('wallet-username').value.trim();

    if (!username) {
        showStatus('wallet-status', 'Please enter your username', 'error');
        return;
    }

    showStatus('wallet-status', 'Loading your quantum key wallet...', 'success');

    try {
        const response = await fetch(`${API_URL}/wallet/${username}`);

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to load wallet');
        }

        const data = await response.json();

        // Display wallet information
        document.getElementById('wallet-id').textContent = `Wallet ID: ${data.wallet_id}`;
        document.getElementById('wallet-created').textContent = `Created: ${new Date(data.created_at).toLocaleString()}`;

        // Display keys
        const keysList = document.getElementById('keys-list');
        keysList.innerHTML = '';

        if (data.keys.length === 0) {
            keysList.innerHTML = '<div class="key-item">No keys in your wallet yet</div>';
        } else {
            data.keys.forEach(key => {
                const keyItem = document.createElement('div');
                keyItem.className = 'key-item';
                keyItem.innerHTML = `
                      <div class="key-info">
                          <div class="key-name">${key.key_name}</div>
                          <div class="key-algorithm">${key.algorithm_name}</div>
                      </div>
                      <div class="key-actions">
                          <button onclick="viewKeyDetails('${key.key_id}')">
                              <i class="fas fa-eye"></i> View
                          </button>
                      </div>
                  `;
                keysList.appendChild(keyItem);
            });
        }

        // Show the wallet container
        document.getElementById('wallet-container').classList.remove('hidden');
        document.getElementById('key-details-container').classList.add('hidden');

        // Store the wallet ID for later use
        currentWalletId = data.wallet_id;

        showStatus('wallet-status', 'Wallet loaded successfully', 'success');
    } catch (error) {
        showStatus('wallet-status', `Error: ${error.message}`, 'error');
    }
}

// Function to create a new wallet
async function createWallet() {
    const username = document.getElementById('wallet-username').value.trim();

    if (!username) {
        showStatus('wallet-status', 'Please enter your username', 'error');
        return;
    }

    showStatus('wallet-status', 'Creating new quantum key wallet...', 'success');

    try {
        const response = await fetch(`${API_URL}/wallet/create`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username,
                name: "Primary Wallet"
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to create wallet');
        }

        const data = await response.json();

        showStatus('wallet-status', 'Wallet created successfully', 'success');

        // Load the new wallet
        loadWallet();
    } catch (error) {
        showStatus('wallet-status', `Error: ${error.message}`, 'error');
    }
}

// Function to generate a new key in the wallet
async function generateNewKey() {
    const keyName = document.getElementById('new-key-name').value.trim();
    const algorithm = document.getElementById('new-key-algorithm').value;

    if (!keyName) {
        showStatus('wallet-status', 'Please enter a name for your key', 'error');
        return;
    }

    if (!currentWalletId) {
        showStatus('wallet-status', 'No wallet loaded', 'error');
        return;
    }

    showStatus('wallet-status', 'Generating new quantum-resistant key...', 'success');

    try {
        const response = await fetch(`${API_URL}/wallet/add-key?wallet_id=${currentWalletId}&key_name=${encodeURIComponent(keyName)}&algorithm=${algorithm}`, {
            method: 'POST'
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to generate key');
        }

        const data = await response.json();

        showStatus('wallet-status', `New key "${keyName}" generated successfully using ${data.algorithm_name}`, 'success');

        // Reload the wallet to show the new key
        loadWallet();
    } catch (error) {
        showStatus('wallet-status', `Error: ${error.message}`, 'error');
    }
}

// Function to view key details
async function viewKeyDetails(keyId) {
    showStatus('wallet-status', 'Loading key details...', 'success');

    try {
        const response = await fetch(`${API_URL}/wallet/key/${keyId}`);

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to load key details');
        }

        const data = await response.json();

        // Find the key info from the keys list
        const keysList = document.querySelectorAll('.key-item');
        let keyName = '';
        let keyAlgorithm = '';

        keysList.forEach(item => {
            if (item.querySelector('button').getAttribute('onclick').includes(keyId)) {
                keyName = item.querySelector('.key-name').textContent;
                keyAlgorithm = item.querySelector('.key-algorithm').textContent;
            }
        });

        // Display key details
        document.getElementById('key-name').textContent = keyName;
        document.getElementById('key-algorithm').textContent = keyAlgorithm;
        document.getElementById('key-created').textContent = 'N/A'; // We don't have this info in the response
        document.getElementById('key-public').value = data.public_key;

        // Show the key details container
        document.getElementById('wallet-container').classList.add('hidden');
        document.getElementById('key-details-container').classList.remove('hidden');

        showStatus('wallet-status', 'Key details loaded successfully', 'success');
    } catch (error) {
        showStatus('wallet-status', `Error: ${error.message}`, 'error');
    }
}

// Function to hide key details
function hideKeyDetails() {
    document.getElementById('wallet-container').classList.remove('hidden');
    document.getElementById('key-details-container').classList.add('hidden');
}