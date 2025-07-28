class LoginForm {

    constructor(containerId, options = {}) {
        document.addEventListener('DOMContentLoaded', () => {
            this.container = document.getElementById(containerId);
            this.onContinue = options.onContinue || (() => {});
            this.isMobilePage = document.body.classList.contains('mobile-page');
            this.render();
            this.attachEvents();
        });
    }

    render() {
        // Add the icon font link if it doesn't exist
        if (!document.querySelector('link[href*="fonts.googleapis.com/icon"]')) {
            const link = document.createElement('link');
            link.rel = 'stylesheet';
            link.href = 'https://fonts.googleapis.com/icon?family=Material+Icons';
            document.head.appendChild(link);
        }

        const loginContainer = document.createElement('div');
        loginContainer.className = 'login-container';

        loginContainer.innerHTML = `
            <div class="login-title">Log in</div>
            <div class="input-label">Username</div>
            <div style="position: relative;">
                <input type="text" 
                    id="username-input" 
                    placeholder="Enter your username"
                    class="username-input">
                <span class="material-icons" 
                    id="biometric-button"
                    style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); margin-top: -8px; line-height: 0; cursor: pointer; color: #000; font-size: 24px; opacity: 0.6;">
                    fingerprint
                </span>
            </div>
            <!--div class="input-label">Password</div>
            <div style="position: relative;">
                <input type="password" 
                    id="password-input" 
                    placeholder="Enter your password"
                    class="username-input">
                <span class="material-icons" 
                    style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); margin-top: -8px; line-height: 0; cursor: pointer; color: #000; font-size: 24px; opacity: 0.6;"
                    onclick="this.textContent = this.textContent === 'visibility' ? 'visibility_off' : 'visibility'; this.previousElementSibling.type = this.previousElementSibling.type === 'password' ? 'text' : 'password'">
                    visibility
                </span>
            </div-->
            <div class="remember-me">
                <input type="checkbox" id="remember-username">
                <label for="remember-username">Remember username</label>
            </div>
            <button class="continue-button">
                CONTINUE
            </button>
            <div class="help-link">
                <a href="#">NEED HELP LOGGING IN?</a>
            </div>
        `;

        this.container.innerHTML = '';
        this.container.appendChild(loginContainer);
    }

    showStatus(message, type = 'error') {
        // Remove any existing status message
        const existingStatus = document.querySelector('.status-message');
        if (existingStatus) {
            existingStatus.remove();
        }

        // Create new status message
        const statusDiv = document.createElement('div');
        statusDiv.className = `status-message ${type}`;
        statusDiv.style.cssText = `
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            padding: 10px 20px;
            border-radius: 4px;
            background-color: ${type === 'error' ? '#f44336' : '#4CAF50'};
            color: white;
            z-index: 1000;
            min-width: 300px;
            text-align: center;
            white-space: nowrap;
        `;
        statusDiv.textContent = message;

        // Add to document
        document.body.appendChild(statusDiv);

        // Remove after 3 seconds
        setTimeout(() => {
            statusDiv.remove();
        }, 3000);
    }

    attachEvents() {
        const usernameInput = this.container.querySelector('#username-input');
        const rememberCheckbox = this.container.querySelector('#remember-username');
        const continueButton = this.container.querySelector('.continue-button');
        const biometricButton = this.container.querySelector('#biometric-button');

        // Load saved username and trigger biometrics if exists
        const savedUsername = this.getCookie('username');
        if (savedUsername) {
            usernameInput.value = savedUsername;
            rememberCheckbox.checked = true;
            
            // Automatically trigger biometric authentication
            setTimeout(async () => {
                try {
                    const success = await mobileStepUp.authenticateWithBiometrics();
                    if (success) {
                        mobileStepUp.showConfirmation(savedUsername);
                    } else {
                        this.showStatus('Biometric authentication failed. Please try again.', 'error');
                    }
                } catch (error) {
                    console.error('Biometric authentication error:', error);
                    this.showStatus('Biometric authentication failed. Please try again.', 'error');
                }
            }, 500); // Small delay to ensure everything is loaded
        }

        // Add biometric button click handler
        biometricButton.addEventListener('click', async () => {
            const username = usernameInput.value.trim();
            if (!username) {
                this.showStatus('Please enter a username', 'error');
                return;
            }

            try {
                const success = await mobileStepUp.authenticateWithBiometrics();
                if (success) {
                    mobileStepUp.showConfirmation(username);
                } else {
                    this.showStatus('Biometric authentication failed. Please try again.', 'error');
                }
            } catch (error) {
                console.error('Biometric authentication error:', error);
                this.showStatus('Biometric authentication failed. Please try again.', 'error');
            }
        });

        // Handle continue button click
        continueButton.addEventListener('click', async () => {
            const username = usernameInput.value.trim();
            if (username) {
                // Handle remember me
                if (rememberCheckbox.checked) {
                    this.setCookie('username', username, 30);
                } else {
                    this.setCookie('username', '', -1);
                }

                if (this.isMobilePage) {
                    // For mobile page, trigger biometrics
                    mobileStepUp.authenticateWithBiometrics().then(success => {
                        if (success) {
                            mobileStepUp.showConfirmation(username);
                        }
                    });
                } else {
                    try {
                        // Get client ID first
                        const clientResponse = await fetch('/register-polling');
                        const clientData = await clientResponse.json();
                        const clientId = clientData.client_id;
                        
                        // Store client ID in localStorage for step-up later
                        localStorage.setItem('clientId', clientId);
                        localStorage.setItem('username', username);
                        
                        // Redirect to dashboard
                        window.location.href = '/dashboard';
                    } catch (error) {
                        console.error('Error during login:', error);
                    }
                }
            }
        });
    }

    // Cookie utilities
    setCookie(name, value, days) {
        const expires = new Date();
        expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
        document.cookie = `${name}=${value};expires=${expires.toUTCString()};path=/`;
    }

    getCookie(name) {
        const nameEQ = name + "=";
        const ca = document.cookie.split(';');
        for(let i = 0; i < ca.length; i++) {
            let c = ca[i];
            while (c.charAt(0) === ' ') c = c.substring(1, c.length);
            if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
        }
        return null;
    }
}

async function startSession(username) {
    try {
        // First get a client ID
        const clientResponse = await fetch('/register-polling');
        const clientData = await clientResponse.json();
        const clientId = clientData.client_id;
        console.log('Got client ID:', clientId);

        // Start session
        const response = await fetch('/start-session', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                client_id: clientId
            })
        });

        if (!response.ok) {
            throw new Error('Failed to start session');
        }

        const data = await response.json();
        console.log('Session started:', data);

        // Initialize SSE connection with the client ID
        const eventSource = new EventSource(`/register-sse/${clientId}`);
        // Setup event listeners...

        return data;
    } catch (error) {
        console.error('Error starting session:', error);
        throw error;
    }
} 