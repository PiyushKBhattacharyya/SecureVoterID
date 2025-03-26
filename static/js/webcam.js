/**
 * Initialize webcam functionality for face capture
 * @param {string} webcamId - ID of the video element
 * @param {string} canvasId - ID of the canvas element for captured image
 * @param {string} dataFieldId - ID of the hidden input field to store image data
 * @param {string} captureBtnId - ID of the capture button
 * @param {string} recaptureBtnId - ID of the recapture button
 * @param {string} submitBtnId - ID of the form submit button
 * @param {string} webcamContainerId - ID of the webcam container div
 * @param {string} capturedContainerId - ID of the captured image container div
 */
function initWebcam(
    webcamId,
    canvasId,
    dataFieldId,
    captureBtnId,
    recaptureBtnId,
    submitBtnId,
    webcamContainerId,
    capturedContainerId
) {
    // Get DOM elements
    const video = document.getElementById(webcamId);
    const canvas = document.getElementById(canvasId);
    const dataField = document.getElementById(dataFieldId);
    const captureBtn = document.getElementById(captureBtnId);
    const recaptureBtn = document.getElementById(recaptureBtnId);
    const submitBtn = document.getElementById(submitBtnId);
    const webcamContainer = document.getElementById(webcamContainerId);
    const capturedContainer = document.getElementById(capturedContainerId);
    
    let stream = null;
    
    // Start webcam
    async function startWebcam() {
        try {
            // Get user media with video only
            stream = await navigator.mediaDevices.getUserMedia({
                video: {
                    width: { ideal: 640 },
                    height: { ideal: 480 },
                    facingMode: 'user'
                },
                audio: false
            });
            
            // Assign stream to video element
            video.srcObject = stream;
            
            // Wait for video to be ready
            await video.play();
            
            // Show capture button
            captureBtn.disabled = false;
            
            // Show webcam container
            webcamContainer.classList.remove('d-none');
            capturedContainer.classList.add('d-none');
            
        } catch (error) {
            console.error('Error accessing webcam:', error);
            alert('Error accessing webcam: ' + error.message);
        }
    }
    
    // Stop webcam
    function stopWebcam() {
        if (stream) {
            stream.getTracks().forEach(track => track.stop());
            video.srcObject = null;
        }
    }
    
    // Capture image from webcam
    function captureImage() {
        if (!video.srcObject) {
            alert('Webcam is not active');
            return;
        }
        
        // Set canvas dimensions to match video
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        
        // Draw video frame to canvas
        const ctx = canvas.getContext('2d');
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        
        // Convert canvas to base64 data URL and store in hidden field
        dataField.value = canvas.toDataURL('image/jpeg', 0.9);
        
        // Stop webcam
        stopWebcam();
        
        // Show captured image and recapture button
        webcamContainer.classList.add('d-none');
        capturedContainer.classList.remove('d-none');
        captureBtn.classList.add('d-none');
        recaptureBtn.classList.remove('d-none');
        
        // Enable submit button
        submitBtn.disabled = false;
    }
    
    // Add event listeners
    captureBtn.addEventListener('click', captureImage);
    
    recaptureBtn.addEventListener('click', () => {
        // Clear data field
        dataField.value = '';
        
        // Hide recapture button, show capture button
        recaptureBtn.classList.add('d-none');
        captureBtn.classList.remove('d-none');
        
        // Disable submit button
        submitBtn.disabled = true;
        
        // Restart webcam
        startWebcam();
    });
    
    // Initialize webcam on page load
    startWebcam();
    
    // Clean up on page unload
    window.addEventListener('beforeunload', stopWebcam);
}
