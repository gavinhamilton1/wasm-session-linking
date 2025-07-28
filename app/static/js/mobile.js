class MobileStepUp {
    constructor() {
        this.sessionId = null;
        this.credentialId = null;
    }

    async init() {
        // Check for saved username
        const savedUsername = getCookie('username');
        if (savedUsername) {
            document.getElementById('username-input').value = savedUsername;
            document.getElementById('remember-username').checked = true;
        }
    }

    async startSession() {
        const usernameInput = document.getElementById('username-input');
        const username = usernameInput.value.trim();
        const rememberUsername = document.getElementById('remember-username').checked;
        
        window.mobileDebug.log(`Starting session for username: ${username}`);
        
        if (!username) {
            window.mobileDebug.error('Please enter a username');
            return;
        }
        
        // Handle remember username
        if (rememberUsername) {
            window.mobileDebug.log('Saving username to cookie');
            setCookie('username', username, 30); // Save for 30 days
        } else {
            window.mobileDebug.log('Removing username from cookie');
            setCookie('username', '', -1); // Remove cookie
        }
        
        // Update email displays
        document.getElementById('confirmation-email').textContent = username;
        document.getElementById('pin-email').textContent = username;
        
        // Show confirmation step
        this.showStep(2);
    }

    async loadPinOptions() {
        try {
            const username = document.getElementById('username-input').value.trim();
            // Update email display in PIN selector screen
            document.getElementById('pin-email').textContent = username;
            
            window.mobileDebug.log('Checking for active session');
            window.mobileDebug.log('API Call - POST /get-pin-options');
            const response = await fetch('/get-pin-options', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username })
            });
            
            if (!response.ok) {
                window.mobileDebug.error(`Server returned status: ${response.status}`);
                throw new Error('No active session found. Please start authentication from your browser first.');
            }
            
            const data = await response.json();
            window.mobileDebug.log('API Response: ' + JSON.stringify(data));
            this.sessionId = data.session_id;
            window.mobileDebug.log(`Mobile: Joined session with ID: ${this.sessionId}`);
            
            const pinOptions = document.getElementById('pin-options');
            const { pins } = data;
            
            window.mobileDebug.log('API Response: ' + JSON.stringify({ pins }));
            
            // Create buttons for each PIN
            if (pins && pins.length > 0) {
                pinOptions.innerHTML = `
                    <div class="pin-grid">
                        ${pins.map(pin => `
                            <button class="pin-option" onclick="mobileStepUp.handlePinSelection(${pin})">
                                ${pin}
                            </button>
                        `).join('')}
                    </div>
                `;
            } else {
                throw new Error('No PIN options received from server');
            }
            
            window.mobileDebug.log('PIN options loaded');
            // Show the PIN selection step
            this.showStep(3);
        } catch (error) {
            window.mobileDebug.error('Error loading PIN options: ' + error);
            pinOptions.innerHTML = `
                <div style="color: red; text-align: center; padding: 20px;">
                    ${error.message}
                    <br><br>
                    <button onclick="mobileStepUp.loadPinOptions()" style="background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px;">
                        Try Again
                    </button>
                </div>`;
        }
    }

    setupMessageInput() {
        const input = document.getElementById('message-input');
        const button = document.getElementById('send-message');
        
        button.onclick = async () => {
            window.mobileDebug.log('Send button clicked');
            
            if (!input.value) {
                window.mobileDebug.log('No message to send');
                return;
            }

            const messageContent = input.value;
            try {
                // Try WebSocket first
                if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                    window.mobileDebug.log('Sending via WebSocket');
                    this.ws.send(JSON.stringify({
                        type: 'message',
                        content: messageContent
                    }));
                    window.mobileDebug.log('Message sent successfully via WebSocket');
                    input.value = '';
                    return;  // Exit early if WebSocket succeeds
                }

                // Fall back to HTTP if WebSocket not available or failed
                window.mobileDebug.log('WebSocket not available, falling back to HTTP');
                const response = await fetch(`/send-message/${this.sessionId}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        type: 'message',
                        content: messageContent
                    })
                });

                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }

                window.mobileDebug.log('Message sent successfully via HTTP');
                input.value = '';
            } catch (error) {
                window.mobileDebug.error('Error sending message: ' + error);
            }
        };
    }

    async registerPushNotifications() {
        try {
            // Register service worker
            const registration = await navigator.serviceWorker.register('/static/service-worker.js');
            console.log('Service Worker registered');

            // Request notification permission
            const permission = await Notification.requestPermission();
            if (permission !== 'granted') {
                throw new Error('Notification permission denied');
            }

            // Get VAPID public key from server
            const response = await fetch('/vapid-public-key');
            const data = await response.json();
            const vapidPublicKey = data.publicKey;

            // Subscribe to push notifications
            const subscription = await registration.pushManager.subscribe({
                userVisibleOnly: true,
                applicationServerKey: this.urlBase64ToUint8Array(vapidPublicKey)
            });

            // Send subscription to server
            await fetch('/register-push', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(subscription)
            });
            
            console.log('Push notification subscription successful');
        } catch (error) {
            console.error('Failed to register for push notifications:', error);
        }
    }

    urlBase64ToUint8Array(base64String) {
        const padding = '='.repeat((4 - base64String.length % 4) % 4);
        const base64 = (base64String + padding)
            .replace(/\-/g, '+')
            .replace(/_/g, '/');

        const rawData = window.atob(base64);
        const outputArray = new Uint8Array(rawData.length);

        for (let i = 0; i < rawData.length; ++i) {
            outputArray[i] = rawData.charCodeAt(i);
        }
        return outputArray;
    }

    async handlePinSelection(pin) {
        try {
            // Get username from input field
            const username = document.getElementById('username-input').value.trim();
            window.mobileDebug.log(`Handling PIN selection for username: ${username}`);
            
            // Get session ID from active session
            const response = await fetch('/get-pin-options', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username })
            });
            
            if (!response.ok) {
                throw new Error('Failed to get session info');
            }
            
            const data = await response.json();
            window.mobileDebug.log(`Got session ID: ${data.session_id}`);
            this.sessionId = data.session_id;  // Store session ID in class
            
            // Send selected PIN to server for verification
            const verifyResponse = await fetch('/verify-pin-selection', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    pin: pin,
                    session_id: this.sessionId
                })
            });
            
            if (!verifyResponse.ok) {
                throw new Error('Failed to verify PIN');
            }
            
            // Server will send success/failure and handle notifications
            const result = await verifyResponse.json();
            if (result.success) {
                this.handleSuccessfulAuth();
            } else {
                const pinOptions = document.getElementById('pin-options');
                pinOptions.innerHTML = `
                    <div style="color: red; text-align: center; padding: 20px;">
                        Incorrect PIN
                    </div>`;
            }
        } catch (error) {
            window.mobileDebug.error('Error handling PIN selection: ' + error);
            const pinOptions = document.getElementById('pin-options');
            pinOptions.innerHTML = `
                <div style="color: red; text-align: center; padding: 20px;">
                    ${error.message}
                    <br><br>
                    <button onclick="mobileStepUp.loadPinOptions()" 
                            style="background: #007bff; color: white; 
                                   padding: 10px 20px; border: none; 
                                   border-radius: 4px;">
                        Try Again
                    </button>
                </div>`;
        }
    }

    async authenticateWithBiometrics() {
        const username = document.getElementById('username-input').value.trim();
        
        if (!username) {
            window.mobileDebug.error('Username is required');
            return false;
        }

        try {
            // Try to authenticate first with strict biometric requirements
            const assertion = await navigator.credentials.get({
                publicKey: {
                    challenge: new Uint8Array(32),
                    rpId: window.location.hostname,
                    userVerification: "required",
                }
            });
            
            if (assertion) {
                window.mobileDebug.log('Successfully authenticated with existing passkey');
                return true;
            }
        } catch (error) {
            // If authentication fails, try registration with strict biometric requirements
            window.mobileDebug.log('No existing passkey, attempting registration');
            try {
                const publicKey = {
                    challenge: new Uint8Array(32),
                    rp: {
                        name: "Stronghold Step-up",
                        id: window.location.hostname
                    },
                    user: {
                        id: new Uint8Array(16),
                        name: username,
                        displayName: username
                    },
                    pubKeyCredParams: [{alg: -7, type: "public-key"}],
                    authenticatorSelection: {
                        authenticatorAttachment: "platform",
                        userVerification: "required",
                        requireResidentKey: true,
                        residentKey: "required"
                    },
                    attestation: "direct",
                    extensions: {
                        credProps: true,
                        uvm: true
                    }
                };

                const credential = await navigator.credentials.create({
                    publicKey
                });
                
                if (credential) {
                    window.mobileDebug.log('Successfully registered new passkey');
                    return true;
                }
            } catch (regError) {
                window.mobileDebug.error('Failed to register passkey: ' + regError);
                return false;
            }
            return false;
        }
        return false;
    }

    handleSuccessfulAuth() {
        try {
            // Show success message
            const pinOptions = document.getElementById('pin-options');
            pinOptions.innerHTML = `
                <div style="text-align: center; padding: 20px;">
                    <h3 style="color: #28a745;">✓ Authentication Successful</h3>
                    <p>You can now close this window and return to your browser.</p>
                    <br><br>
                    <button onclick="#" class="payment-button">Return to dashboard</button>
                </div>
            `;
            
            // Send auth complete to server
            fetch(`/auth-complete/${this.sessionId}`, {
                method: 'POST'
            }).catch(error => {
                window.mobileDebug.error('Error sending auth complete:', error);
            });
            
        } catch (error) {
            window.mobileDebug.error('Error in handleSuccessfulAuth: ' + error);
            const pinOptions = document.getElementById('pin-options');
            pinOptions.innerHTML = '<div style="color: red; text-align: center; padding: 20px;">Error completing authentication. Please try again.</div>';
        }
    }

    showStep(stepNumber) {
        // Hide all steps
        document.querySelectorAll('.step').forEach(step => {
            step.classList.remove('active');
        });
        // Show requested step
        document.getElementById(`step${stepNumber}`).classList.add('active');
        // Show footer only on login step
        document.body.classList.toggle('show-footer', stepNumber === 1);
    }

    async showConfirmation(username) {
        document.getElementById('confirmation-email').textContent = username;
        const confirmationContent = document.getElementById('confirmation-content');
        
        try {
            // Check for active session
            const response = await fetch('/get-pin-options', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username })
            });
            
            if (response.ok) {
                // Session exists, show yes/no options
                confirmationContent.innerHTML = `
                    <div class="auth-question">
                        Are you trying to authenticate on another device?
                    </div>
                    
                    <div class="choice-buttons">
                        <button class="choice-button no" onclick="mobileStepUp.showStep(1)">
                            ✕ NO
                        </button>
                        <button class="choice-button yes" onclick="mobileStepUp.loadPinOptions()">
                            ✓ YES
                        </button>
                    </div>
                `;
            } else {
                // No active session
                confirmationContent.innerHTML = `
                    <div style="text-align: center; padding: 20px;">
                        <h3 style="color: #dc3545;">No Active Session</h3>
                        <p>There is no authentication request for this username.</p>
                        <button onclick="mobileStepUp.showStep(1)" 
                                style="margin-top: 20px; padding: 10px 20px; 
                                       background: #007bff; color: white; 
                                       border: none; border-radius: 4px; 
                                       cursor: pointer;">
                            Return to Login
                        </button>
                    </div>
                `;
            }
        } catch (error) {
            console.error('Error checking session:', error);
            confirmationContent.innerHTML = `
                <div style="text-align: center; padding: 20px;">
                    <h3 style="color: #dc3545;">Error</h3>
                    <p>Failed to check authentication status. Please try again.</p>
                    <button onclick="mobileStepUp.showStep(1)" 
                            style="margin-top: 20px; padding: 10px 20px; 
                                   background: #007bff; color: white; 
                                   border: none; border-radius: 4px; 
                                   cursor: pointer;">
                        Return to Login
                    </button>
                </div>
            `;
        }

        this.showStep(2);
    }
}

// Initialize after DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.mobileStepUp = new MobileStepUp();
    mobileStepUp.init();
});

// Function to show messages to the user
function showMessage(message, type = 'info') {
    mobileDebug.log(`${type}: ${message}`);
    // You could also add a visual indicator here if desired
}

// Handle PIN options display
async function displayPinOptions() {
    try {
        const response = await fetch('/get-pin-options');
        const data = await response.json();
        
        const pinOptionsContainer = document.getElementById('pin-options');
        pinOptionsContainer.innerHTML = '';
        
        data.pins.forEach(pin => {
            const button = document.createElement('button');
            button.className = 'pin-option';
            button.textContent = pin;
            button.onclick = () => handlePinSelection(pin);
            pinOptionsContainer.appendChild(button);
        });
    } catch (error) {
        console.error('Error getting PIN options:', error);
        mobileDebug.error('Failed to get PIN options');
    }
}

// Cookie handling functions
function setCookie(name, value, days) {
    const expires = new Date();
    expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
    document.cookie = `${name}=${value};expires=${expires.toUTCString()};path=/`;
}

function getCookie(name) {
    const nameEQ = name + "=";
    const ca = document.cookie.split(';');
    for(let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) === ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
} 