class Stronghold {
  constructor() {
    this.eventSource = null;
    this.containerElement = null;
    this.timerInterval = null;
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

  async initializeStepUp(containerElementId, sseUrl) {
    console.log('Initializing step-up with container:', containerElementId);
    
    this.containerElement = document.getElementById(containerElementId);
    if (!this.containerElement) {
        throw new Error('Container element not found');
    }

    if (this.eventSource) {
        console.log('Closing existing SSE connection');
        this.eventSource.close();
    }

    // Create new SSE connection
    console.log('Creating new SSE connection to:', sseUrl);
    this.eventSource = new EventSource(sseUrl);
    
    // Get client ID from response headers
    return new Promise((resolve, reject) => {
        this.eventSource.onopen = () => {
            console.log('SSE connection opened');
            // Get client ID from custom header in the first message
            this.eventSource.onmessage = (event) => {
                const clientId = JSON.parse(event.data).client_id;
                console.log('Got client ID from SSE:', clientId);
                
                // Remove the onmessage handler and set up event listeners
                this.eventSource.onmessage = null;
                this.setupEventListeners();
                
                resolve(clientId);
            };
        };
        
        this.eventSource.onerror = (error) => {
            console.error('SSE connection error:', error);
            this.eventSource.close();
            reject(error);
        };
    });
  }

  setupEventListeners() {
    // Listen for step-up initiation
    this.eventSource.addEventListener('step_up_initiated', (event) => {
        console.log('Received step-up initiated event:', event);
        console.log('Event data:', event.data);
        try {
            const stepUpId = JSON.parse(event.data);
            console.log('Received step-up ID:', stepUpId);
            this.handleStepUpInitiated(stepUpId);
        } catch (error) {
            console.error('Error processing step-up event:', error);
            console.error('Raw event data:', event.data);
        }
    });

    // Listen for auth complete
    this.eventSource.addEventListener('auth_complete', (event) => {
        console.log('Received auth complete event');
        // Update AAL level
        const authLevelDiv = document.getElementById('auth-level');
        const downgradeButton = document.getElementById('downgrade-button');
        const qrContainer = document.getElementById('qr-container');
        
        // Remove QR code container if it exists
        if (qrContainer) {
            qrContainer.remove();
        }
        
        authLevelDiv.textContent = 'Auth Level: AAL3';
        authLevelDiv.style.color = '#fd7e14';
        downgradeButton.style.display = 'block';
        localStorage.setItem('authLevel', 'AAL3');
        this.aalUpdated = true;

        // Start 20-second timer instead of 10
        this.startAALTimer(20);
    });

    // Listen for mobile messages
    this.eventSource.addEventListener('mobile_message', (event) => {
        console.log('Received mobile message:', event);
        try {
            const messageEl = document.createElement('div');
            messageEl.style.margin = '10px';
            messageEl.style.padding = '10px';
            messageEl.style.background = '#f0f0f0';
            messageEl.style.borderRadius = '4px';
            messageEl.style.maxWidth = '80%';
            messageEl.style.wordBreak = 'break-word';
            
            const messageText = document.createElement('p');
            messageText.style.margin = '0';
            messageText.textContent = event.data;
            messageEl.appendChild(messageText);
            
            this.containerElement.appendChild(messageEl);
            this.containerElement.scrollTop = this.containerElement.scrollHeight;
        } catch (error) {
            console.error('Error displaying message:', error);
        }
    });
  }

  async handleStepUpInitiated(stepUpId) {
    console.log('Handling step-up initiation with ID:', stepUpId);
    try {
        // Clear the container
        this.containerElement.innerHTML = '';
        
        // Create display container
        const container = document.createElement('div');
        container.style.textAlign = 'center';
        container.style.padding = '20px';
        container.id = 'qr-container';  // Add ID for easy removal
        
        // Create QR code container
        const qrContainer = document.createElement('canvas');
        qrContainer.id = 'qr-code';
        
        // Create step-up ID display
        const stepUpDisplay = document.createElement('p');
        stepUpDisplay.textContent = stepUpId;
        stepUpDisplay.style.fontFamily = 'monospace';
        stepUpDisplay.style.marginTop = '20px';
        
        // Add elements to container
        container.appendChild(qrContainer);
        container.appendChild(stepUpDisplay);
        this.containerElement.appendChild(container);
        
        console.log('Generating QR code for step-up ID');
        // Generate QR code
        QRCode.toCanvas(
            qrContainer,
            stepUpId,
            {
                width: 256,
                margin: 2,
                color: {
                    dark: '#000000',
                    light: '#ffffff'
                }
            }
        );
        console.log('QR code generated successfully');
    } catch (error) {
        console.error('Error displaying step-up ID:', error);
        this.containerElement.innerHTML = `Error: ${error.message}`;
    }
  }

  handleStepUpCompleted() {
    console.log('Handling step-up completion');
    
    // Clear container and show completion message
    this.containerElement.innerHTML = `
      <div class="step-up-complete" style="text-align: center; padding: 20px;">
        <h3>Step-up Complete</h3>
      </div>
    `;

    // Close SSE connection as it's no longer needed
    if (this.eventSource) {
      console.log('Closing SSE connection');
      this.eventSource.close();
      this.eventSource = null;
    }
  }

  async startStepUp() {
    console.log('Starting step-up process');
    try {
        // Initialize new SSE connection
        const clientId = await this.initializeStepUp('step-up-container', '/register-sse');
        console.log('Got client ID:', clientId);
        
        // Initiate step-up
        const result = await fetch(`/initiate-step-up/${clientId}`, {
            method: 'POST'
        });
        const data = await result.json();
        console.log('Step-up initiated response:', data);
        
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
}
