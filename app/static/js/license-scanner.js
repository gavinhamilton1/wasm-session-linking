class LicenseScanner {
    constructor() {
        this.video = document.getElementById('video');
        this.canvas = document.getElementById('canvas');
        this.captureButton = document.getElementById('capture-button');
        this.resultsDiv = document.querySelector('.results');
        this.facePreview = document.getElementById('face-preview');
        this.nameResult = document.getElementById('name-result');
        this.licenseNumberResult = document.getElementById('license-number-result');
        this.confirmButton = document.getElementById('confirm-button');
        this.retryButton = document.getElementById('retry-button');
        this.fullCapturePreview = document.getElementById('full-capture-preview');
        
        this.initCamera();
        this.attachEvents();
    }

    async initCamera() {
        try {
            // Get list of supported resolutions
            const devices = await navigator.mediaDevices.enumerateDevices();
            const videoConstraints = {
                facingMode: 'environment',
                width: { min: 1280, ideal: 1920, max: 2560 },
                height: { min: 720, ideal: 1080, max: 1440 }
            };

            const stream = await navigator.mediaDevices.getUserMedia({
                video: videoConstraints
            });

            this.video.srcObject = stream;
            
            // Wait for video to be ready
            await new Promise(resolve => this.video.onloadedmetadata = resolve);
            
            // Get the actual track settings
            const track = stream.getVideoTracks()[0];
            const settings = track.getSettings();
            console.log('Camera initialized with resolution:', settings.width, 'x', settings.height);
            console.log('Available settings:', settings);

        } catch (err) {
            console.error('Error accessing camera:', err);
            alert('Unable to access camera. Please ensure you have granted camera permissions.');
        }
    }

    attachEvents() {
        this.captureButton.addEventListener('click', () => this.captureLicense());
        this.confirmButton.addEventListener('click', () => this.confirmScan());
        this.retryButton.addEventListener('click', () => this.retry());
    }

    async captureLicense() {
        console.log('Capturing license...');
        
        // Set canvas to full video resolution
        this.canvas.width = this.video.videoWidth;
        this.canvas.height = this.video.videoHeight;
        
        // Get dimensions
        const scanArea = document.querySelector('.scan-area').getBoundingClientRect();
        const videoRect = this.video.getBoundingClientRect();
        
        // Calculate scaling factors from display size to actual video size
        // const scaleX = this.video.videoWidth / videoRect.width;
        // const scaleY = this.video.videoHeight / videoRect.height;
        
        // Calculate crop region in video coordinates with different padding for each side
        // const paddingTop = 40 * scaleY;    // More padding at the top
        // const paddingBottom = 20 * scaleY;  // Standard padding at bottom
        // const paddingLeft = 10 * scaleX;    // Less padding on sides
        // const paddingRight = 10 * scaleX;   // Less padding on sides
        
        // const cropX = Math.max(0, (scanArea.left - videoRect.left) * scaleX - paddingLeft);
        // const cropY = Math.max(0, (scanArea.top - videoRect.top) * scaleY - paddingTop);
        // const cropWidth = Math.min(
        //     scanArea.width * scaleX + (paddingLeft + paddingRight),
        //     this.video.videoWidth - cropX
        // );
        // const cropHeight = Math.min(
        //     scanArea.height * scaleY + (paddingTop + paddingBottom),
        //     this.video.videoHeight - cropY
        // );

        // console.log('Dimensions:', {
        //     video: videoRect,
        //     scan: scanArea,
        //     scale: { x: scaleX, y: scaleY },
        //     crop: { x: cropX, y: cropY, width: cropWidth, height: cropHeight },
        //     padding: { top: paddingTop, bottom: paddingBottom, left: paddingLeft, right: paddingRight }
        // });

        // Draw and crop the image
        const ctx = this.canvas.getContext('2d');
        ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
        
        // First draw the full video frame
        ctx.drawImage(this.video, 0, 0);
        
        // Then get just the cropped region
//        const imageData = ctx.getImageData(cropX, cropY, cropWidth, cropHeight);
        
        // Resize canvas to cropped size
        // this.canvas.width = cropWidth;
        // this.canvas.height = cropHeight;
        
        // Put the cropped image data
        ctx.putImageData(ctx.getImageData(0, 0, this.canvas.width, this.canvas.height), 0, 0);

        // Get the final image
        const finalImage = this.canvas.toDataURL('image/jpeg', 1.0);
        
        // Show preview immediately
        this.resultsDiv.style.display = 'block';
        this.fullCapturePreview.src = finalImage;
        this.facePreview.src = finalImage;
        this.nameResult.textContent = 'Processing...';
        this.licenseNumberResult.textContent = 'Processing...';

        // Small delay to ensure UI updates before processing
        await new Promise(resolve => setTimeout(resolve, 100));

        console.log('Image captured, sending to server...');

        try {
            const response = await fetch('/api/upload_id', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ image: finalImage })
            });

            const result = await response.json();
            console.log('Server response:', result);

            if (result.success) {
                // Update just the text and face image, keeping the full capture
                this.nameResult.textContent = result.data.name || 'Not found';
                this.licenseNumberResult.textContent = result.data.license_number || 'Not found';
                if (result.data.face_image) {
                    this.facePreview.src = result.data.face_image;
                }
                if (result.data.processed_image) {
                    document.getElementById('processed-preview').src = result.data.processed_image;
                }
            } else {
                throw new Error(result.error || 'Failed to process image');
            }
        } catch (err) {
            console.error('Error processing image:', err);
            alert('Error processing image. Please try again.');
            this.retry();  // Hide results on error
        }
    }

    parseResults(text) {
        console.log('Raw OCR text:', text);
        const lines = text.split('\n');
        let name = '';
        let licenseNumber = '';

        // Improved parsing for New Jersey license format
        for (const line of lines) {
            const cleanLine = line.trim().toUpperCase();
            
            // Look for name (typically after "4d")
            if (cleanLine.includes('4D')) {
                name = cleanLine.split('4D')[1]?.trim() || '';
            }
            
            // Look for license number (typically 15 characters)
            const licenseMatch = cleanLine.match(/[A-Z][0-9]{14}/);
            if (licenseMatch) {
                licenseNumber = licenseMatch[0];
            }
        }

        return {
            name,
            licenseNumber
        };
    }

    showResults(name, licenseNumber, capturedImage, faceImage) {
        console.log('Showing results:', { name, licenseNumber });
        
        // Update the text content
        this.nameResult.textContent = name || 'Not found';
        this.licenseNumberResult.textContent = licenseNumber || 'Not found';
        
        // Show both the full capture and face image
        this.fullCapturePreview.src = capturedImage;
        this.facePreview.src = faceImage || capturedImage;
        
        // Make sure the results div is visible
        this.resultsDiv.style.display = 'block';
        
        // Scroll to results if needed
        this.resultsDiv.scrollIntoView({ behavior: 'smooth' });
    }

    confirmScan() {
        // Send data to server
        const data = {
            name: this.nameResult.textContent,
            licenseNumber: this.licenseNumberResult.textContent,
            faceImage: this.facePreview.src
        };

        fetch('/api/save-license', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        })
        .then(response => response.json())
        .then(result => {
            if (result.success) {
                window.location.href = '/verification-complete';
            }
        })
        .catch(err => {
            console.error('Error saving data:', err);
            alert('Error saving data. Please try again.');
        });
    }

    retry() {
        this.resultsDiv.style.display = 'none';
    }
}

// Initialize scanner when page loads
document.addEventListener('DOMContentLoaded', () => {
    new LicenseScanner();
}); 