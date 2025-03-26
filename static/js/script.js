// Global utility functions for the Voter Verification System

/**
 * Validate an email address format
 * @param {string} email - The email to validate
 * @returns {boolean} - Whether the email is valid
 */
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

/**
 * Validate a phone number
 * @param {string} phone - The phone number to validate
 * @returns {boolean} - Whether the phone is valid
 */
function validatePhone(phone) {
    // Basic validation for phone numbers, can be adjusted for specific formats
    return /^\d{10,15}$/.test(phone.replace(/[-()\s]/g, ''));
}

/**
 * Enable or disable form submit button based on form validity
 * @param {string} formId - The ID of the form element
 * @param {string} submitBtnId - The ID of the submit button
 */
function enableSubmitIfFormValid(formId, submitBtnId) {
    const form = document.getElementById(formId);
    const submitBtn = document.getElementById(submitBtnId);
    
    if (!form || !submitBtn) return;
    
    const inputs = form.querySelectorAll('input[required]');
    let isValid = true;
    
    inputs.forEach(input => {
        if (!input.value.trim()) {
            isValid = false;
        }
        
        if (input.type === 'email' && !validateEmail(input.value)) {
            isValid = false;
        }
        
        if (input.id === 'phone' && !validatePhone(input.value)) {
            isValid = false;
        }
    });
    
    submitBtn.disabled = !isValid;
}

/**
 * Display a custom alert/toast message
 * @param {string} message - The message to display
 * @param {string} type - The type of alert ('success', 'danger', 'warning', 'info')
 */
function showAlert(message, type = 'info') {
    // Create alert element
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed top-0 end-0 m-3`;
    alertDiv.setAttribute('role', 'alert');
    alertDiv.style.zIndex = '9999';
    
    // Alert content
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    // Add to document
    document.body.appendChild(alertDiv);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        alertDiv.classList.remove('show');
        setTimeout(() => alertDiv.remove(), 150);
    }, 5000);
}

// Execute when DOM is fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Add event listeners for form validation if needed
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        const inputs = form.querySelectorAll('input');
        inputs.forEach(input => {
            input.addEventListener('input', () => {
                // Remove validation styling when user starts typing again
                input.classList.remove('is-invalid');
            });
        });
    });
});
