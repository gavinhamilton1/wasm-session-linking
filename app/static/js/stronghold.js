class Stronghold {
  constructor() {
    this.eventSource = null;
    this.containerElement = null;
    this.timerInterval = null;
    this.pollingInterval = null;
    this.clientId = null;
    this.currentClientId = null;  // Store the current client ID
    this.sessionId = null;
    this.ws = null;  // Add WebSocket property
    this.initializeAALLevel();
    console.log('Stronghold initialized');
  }

  initializeAALLevel() {
    const savedAAL = localStorage.getItem('authLevel');
    const authLevelDiv = document.getElementById('auth-level');
    const downgradeButton = document.getElementById('downgrade-button');
    
    if (savedAAL === 'AAL3') {
      authLevelDiv.textContent = 'Auth Level: AAL3';
      authLevelDiv.style.color = '#fd7e14';
      downgradeButton.style.display = 'block';
      this.aalUpdated = true;
    }
  }

  startAALTimer(seconds) {
    let timeLeft = seconds;
    const authLevelDiv = document.getElementById('auth-level');
    const timerSpan = document.createElement('span');
    timerSpan.style.marginLeft = '10px';
    timerSpan.style.fontSize = '14px';
    timerSpan.style.color = '#666';
    authLevelDiv.appendChild(timerSpan);

    this.timerInterval = setInterval(() => {
      timeLeft--;
      timerSpan.textContent = `(${timeLeft}s)`;
      
      if (timeLeft <= 0) {
        clearInterval(this.timerInterval);
        this.downgradeAAL();
        this.startStepUp();  // Start new step-up process
      }
    }, 1000);
  }

  downgradeAAL() {
    clearInterval(this.timerInterval);  // Clear any existing timer
    const authLevelDiv = document.getElementById('auth-level');
    const downgradeButton = document.getElementById('downgrade-button');
    
    // Remove timer if it exists
    const timerSpan = authLevelDiv.querySelector('span');
    if (timerSpan) {
      timerSpan.remove();
    }

    authLevelDiv.textContent = 'Auth Level: AAL2';
    authLevelDiv.style.color = '#28a745';
    downgradeButton.style.display = 'none';
    localStorage.removeItem('authLevel');
    this.aalUpdated = false;
  }

  async initializeSession(sessionId) {
    console.log('Initializing session with ID:', sessionId);
    this.sessionId = sessionId;
    await this.setupWebSocket();
  }

  async setupWebSocket() {
    if (this.ws) {
      this.ws.close();
    }
    
    console.log('Setting up WebSocket for session:', this.sessionId);
    return new Promise((resolve, reject) => {
      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${wsProtocol}//${window.location.host}/ws/${this.sessionId}`;
      console.log('Connecting to WebSocket URL:', wsUrl);
      this.ws = new WebSocket(wsUrl);
      
      this.ws.onmessage = (event) => {
        console.log('WebSocket message received:', event.data);
        let data;
        try {
          data = JSON.parse(event.data);
        } catch (e) {
          console.error('Failed to parse WebSocket message:', e);
          return;
        }
        
        if (data.type === 'auth_complete') {
          console.log('Received auth_complete via WebSocket');
          this.handleAuthComplete();
        } else if (data.type === 'auth_failed') {
          console.log('Received auth_failed via WebSocket');
          this.handleAuthFailed();
        }
      };
      
      this.ws.onopen = () => {
        console.log('WebSocket connection opened');
        resolve();
      };
      
      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        reject(error);
      };
      
      this.ws.onclose = () => {
        console.log('WebSocket connection closed');
      };
    });
  }

  handleWebSocketMessage(data) {
    console.log('WebSocket message received:', data);
    switch (data.type) {
      case 'auth_complete':
        this.handleAuthComplete();
        break;
      case 'mobile_message':
        this.handleMobileMessage(data.content);
        break;
      default:
        console.warn('Unknown message type:', data.type);
    }
  }

  handleAuthComplete() {
    console.log('Handling auth complete event');
    // Update auth level
    const authLevelDiv = document.getElementById('auth-level');
    if (authLevelDiv) {
      console.log('Updating auth level display');
      authLevelDiv.textContent = 'Auth Level: AAL3';
      authLevelDiv.style.color = '#fd7e14';
      localStorage.setItem('authLevel', 'AAL3');
    }
    
    // Show downgrade button
    const downgradeButton = document.getElementById('downgrade-button');
    if (downgradeButton) {
      console.log('Showing downgrade button');
      downgradeButton.style.display = 'block';
    }
    
    // Update step-up container
    const pinContainer = document.querySelector('.pin-container');
    if (pinContainer) {
      pinContainer.innerHTML = `
        <div style="text-align: center;">
          <h3 style="color: #28a745;">✓ PIN Verified</h3>
          <button onclick="closeAuthOverlay()" style="margin-top: 20px; padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer;">Continue</button>
        </div>
      `;
    }
    
    // Start AAL timer
    //console.log('Starting AAL timer');
    //this.startAALTimer(20);
  }

  handleMobileMessage(content) {
    console.log('Mobile message received:', content);
    const messageBox = document.getElementById('pin-message-box');
    const messageDiv = document.createElement('div');
    messageDiv.textContent = content;
    messageBox.appendChild(messageDiv);
  }

  async startStepUp() {
    console.log('Starting step-up process');
    try {
      // Get username from localStorage
      const username = localStorage.getItem('username');
      
      // Start session
      const sessionResponse = await fetch('/start-session', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          username: username
        })
      });

      const sessionData = await sessionResponse.json();
      console.log('Session started:', sessionData);
      this.sessionId = sessionData.session_id;

      // Initialize WebSocket connection
      await this.initializeWebSocket();

      // Clear any existing status
      const statusDiv = document.getElementById('status');
      if (statusDiv) {
        statusDiv.textContent = '';
        statusDiv.className = '';
      }
    } catch (error) {
      console.error('Step-up error:', error);
      const statusDiv = document.getElementById('status');
      if (statusDiv) {
        statusDiv.textContent = 'Error starting step-up: ' + error.message;
        statusDiv.className = 'status error';
      }
    }
  }

  async initializeWebSocket() {
    if (this.ws) {
      this.ws.close();
    }

    this.ws = new WebSocket(`wss://${window.location.host}/ws/${this.sessionId}`);
    console.log('WebSocket connection initialized with session ID:', this.sessionId);

    this.ws.onopen = () => {
      console.log('WebSocket connection opened successfully');
    };
    
    this.ws.onerror = (error) => {
      console.error('WebSocket connection error:', error);
    };

    // Setup event listeners
    this.setupEventListeners();
  }

  handleAuthFailed() {
    console.log('Handling auth failed event');
    const pinContainer = document.querySelector('.pin-container');
    if (pinContainer) {
      pinContainer.innerHTML = `
        <div style="text-align: center;">
          <h3 style="color: #dc3545;">✕ Incorrect PIN</h3>
          <button onclick="resetAndShowLogin()" 
                  style="margin-top: 20px; padding: 10px 20px; 
                         background: #007bff; color: white; 
                         border: none; border-radius: 4px; 
                         cursor: pointer;">
            Return to Login
          </button>
        </div>
      `;
    }
    
    // Delete the failed session
    if (this.sessionId) {
      console.log('Deleting failed session:', this.sessionId);
      fetch(`/delete-session/${this.sessionId}`, {
        method: 'DELETE'
      }).then(() => {
        console.log('Session deleted successfully');
      }).catch(error => {
        console.error('Error deleting session:', error);
      });
    }
    
    // Clear any existing polling interval
    if (this.pollingInterval) {
      clearInterval(this.pollingInterval);
    }
    
    // Close WebSocket connection
    if (this.ws) {
      this.ws.close();
    }
  }

  handleAuthLevelChange(level) {
    console.log('Auth level changed to:', level);
    const authLevelDiv = document.getElementById('auth-level');
    const downgradeButton = document.getElementById('downgrade-button');
    
    if (level === 'AAL3') {
      authLevelDiv.textContent = 'Auth Level: AAL3';
      downgradeButton.style.display = 'block';
    } else {
      authLevelDiv.textContent = 'Auth Level: AAL2';
      downgradeButton.style.display = 'none';
    }
  }

  async setupSSE() {
    return new Promise((resolve, reject) => {
      let timeoutId = setTimeout(() => {
        console.error('SSE connection timed out');
        this.eventSource.close();
        reject(new Error('SSE connection timed out'));
      }, 3000);  // Reduced timeout to 3 seconds

      // Add connection timeout check
      let connectionTimeoutId = setTimeout(() => {
        console.error('SSE connection blocked or too slow');
        this.eventSource.close();
        reject(new Error('SSE connection blocked'));
      }, 1000);  // Check if connection is established within 1 second

      this.eventSource.onopen = () => {
        console.log('SSE connection opened');
        clearTimeout(connectionTimeoutId);
      };

      this.eventSource.onmessage = (event) => {
        clearTimeout(timeoutId);
        clearTimeout(connectionTimeoutId);
        const clientId = JSON.parse(event.data).client_id;
        this.clientId = clientId;
        console.log('Got client ID from SSE:', clientId);
        this.setupEventListeners();
        resolve(clientId);
      };

      this.eventSource.onerror = (error) => {
        clearTimeout(timeoutId);
        clearTimeout(connectionTimeoutId);
        console.error('SSE connection error:', error);
        this.eventSource.close();
        reject(error);
      };
    });
  }

  async setupPolling() {
    if (this.pollingInterval) {
      clearInterval(this.pollingInterval);
    }
    
    console.log('Setting up polling for session:', this.sessionId);
    this.pollingInterval = setInterval(async () => {
      try {
        console.log('Polling for updates...');
        const response = await fetch(`/poll-updates/${this.sessionId}`);
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const updates = await response.json();
        console.log('Polling received updates:', updates);
        
        if (updates.events && updates.events.length > 0) {
          updates.events.forEach(event => {
            console.log('Processing event:', event);
            if (event.type === 'auth_complete') {
              console.log('Received auth_complete event, handling...');
              this.handleAuthComplete();
              // Clear polling interval after successful auth
              clearInterval(this.pollingInterval);
            }
          });
        }
      } catch (error) {
        console.error('Polling error:', error);
      }
    }, 1000);
  }

  setupEventListeners() {
    console.log('Setting up event listeners');
    
    this.ws.onmessage = (event) => {
      console.log('Message received:', event.data);
      try {
        const message = JSON.parse(event.data);
        if (message.type === 'auth_complete') {
          this.handleAuthComplete();
        } else if (message.type === 'auth_failed') {
          this.handleAuthFailed();
        }
      } catch (error) {
        console.error('Error processing message:', error);
      }
    };
  }

  setupPollingEventHandlers() {
    console.log('Setting up polling event handlers');
    this.eventHandlers = {
      'step_up_initiated': (data) => {
        console.log('Polling: Received step-up initiated:', data);
        this.handleStepUpInitiated(data);
      },
      'auth_complete': () => {
        console.log('Polling: Received auth complete');
        this.handleAuthComplete();  // Use the shared handler
      },
      'mobile_message': (data) => {
        console.log('Polling: Received mobile message:', data);
        // Clear the container if it's the first message after auth
        if (this.containerElement.children.length === 1 && 
          this.containerElement.children[0].textContent === 'Messages will appear here...') {
          this.containerElement.innerHTML = '';
        }
        this.handleMobileMessage(data);
      }
    };
  }

  async handleStepUpInitiated(stepUpId) {
    console.log('Handling step-up initiation with ID:', stepUpId);
    try {
      console.log('Step-up ID received:', stepUpId);
    } catch (error) {
      console.error('Error displaying step-up ID:', error);
    }
  }

  handleStepUpCompleted() {
    console.log('Handling step-up completion');
    this.handleAuthComplete();
  }
}
