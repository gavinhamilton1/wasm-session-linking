class ImageUploader {
    constructor() {
        this.uploadContainer = document.getElementById('upload-container');
        this.fileInput = document.getElementById('image-upload');
        this.preview = document.getElementById('preview');
        this.continueBtn = document.getElementById('continue-btn');
        this.rotation = 0;
        this.originalImage = null;
        this.maxPreviewWidth = 800; // Maximum preview width
        this.maxPreviewHeight = 600; // Maximum preview height
        this.setupEventListeners();
    }

    setupEventListeners() {
        // Click to upload
        this.uploadContainer.addEventListener('click', () => {
            this.fileInput.click();
        });

        // File selection handler
        this.fileInput.addEventListener('change', (e) => {
            if (e.target.files[0]) {
                this.handleFileSelect(e.target.files[0]);
            }
        });

        // Drag and drop handlers
        this.uploadContainer.addEventListener('dragover', (e) => {
            e.preventDefault();
            this.uploadContainer.style.borderColor = '#0066ff';
            this.uploadContainer.style.background = '#f0f8ff';
        });

        this.uploadContainer.addEventListener('dragleave', (e) => {
            e.preventDefault();
            this.uploadContainer.style.borderColor = '#ccc';
            this.uploadContainer.style.background = '#f8f9fa';
        });

        this.uploadContainer.addEventListener('drop', (e) => {
            e.preventDefault();
            this.uploadContainer.style.borderColor = '#ccc';
            this.uploadContainer.style.background = '#f8f9fa';
            
            const file = e.dataTransfer.files[0];
            if (file && file.type.startsWith('image/')) {
                this.handleFileSelect(file);
            }
        });

        // Continue button handler
        this.continueBtn.addEventListener('click', () => this.uploadImage());

        // Add rotation button handlers
        document.querySelectorAll('.rotate-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const degrees = parseInt(btn.dataset.degrees);
                this.rotateImage(degrees);
            });
        });
    }

    handleFileSelect(file) {
        // Show preview
        const reader = new FileReader();
        reader.onload = (e) => {
            this.originalImage = e.target.result;
            
            // Create scaled preview
            const img = new Image();
            img.onload = () => {
                const { width, height } = this.calculateScaledDimensions(img.width, img.height);
                
                // Create preview canvas
                const previewCanvas = document.createElement('canvas');
                previewCanvas.width = width;
                previewCanvas.height = height;
                const ctx = previewCanvas.getContext('2d');
                ctx.drawImage(img, 0, 0, width, height);
                
                // Update preview
                this.preview.src = previewCanvas.toDataURL('image/jpeg');
                this.preview.style.display = 'block';
                document.querySelector('.controls').style.display = 'block';
                document.querySelector('.image-controls').style.display = 'block';
            };
            img.src = this.originalImage;
        };
        reader.readAsDataURL(file);
        
        // Update upload container text
        document.querySelector('.primary-text').textContent = file.name;
    }

    calculateScaledDimensions(width, height) {
        let newWidth = width;
        let newHeight = height;
        
        // Scale down if image is too large
        if (width > this.maxPreviewWidth || height > this.maxPreviewHeight) {
            const ratioWidth = this.maxPreviewWidth / width;
            const ratioHeight = this.maxPreviewHeight / height;
            const ratio = Math.min(ratioWidth, ratioHeight);
            
            newWidth = width * ratio;
            newHeight = height * ratio;
        }
        
        return { width: newWidth, height: newHeight };
    }

    rotateImage(degrees) {
        this.rotation = (this.rotation + degrees) % 360;
        this.preview.style.transform = `rotate(${this.rotation}deg)`;
    }

    async uploadImage() {
        try {
            this.continueBtn.disabled = true;
            this.continueBtn.textContent = 'Uploading...';

            // Create a canvas for the full resolution rotated image
            const img = new Image();
            await new Promise((resolve, reject) => {
                img.onload = resolve;
                img.onerror = reject;
                img.src = this.originalImage;
            });

            const canvas = document.createElement('canvas');
            if (this.rotation % 180 === 0) {
                canvas.width = img.width;
                canvas.height = img.height;
            } else {
                canvas.width = img.height;
                canvas.height = img.width;
            }

            const ctx = canvas.getContext('2d');
            ctx.save();
            ctx.translate(canvas.width / 2, canvas.height / 2);
            ctx.rotate(this.rotation * Math.PI / 180);
            ctx.drawImage(img, -img.width / 2, -img.height / 2);
            ctx.restore();

            // Get blob with proper MIME type
            const blob = await new Promise(resolve => 
                canvas.toBlob(resolve, 'image/jpeg', 0.95)
            );

            if (!blob) {
                throw new Error('Failed to create image blob');
            }

            const formData = new FormData();
            formData.append('file', blob, 'template.jpg');

            const response = await fetch('/api/upload_id', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            if (data.success) {
                console.log('Upload successful:', data);
            } else {
                throw new Error(data.error || 'Upload failed');
            }
        } catch (error) {
            console.error('Upload error:', error);
            alert('Error uploading image: ' + error.message);
            this.continueBtn.disabled = false;
            this.continueBtn.textContent = 'Continue to Template Editor';
        }
    }
}

// Initialize uploader
window.imageUploader = new ImageUploader(); 