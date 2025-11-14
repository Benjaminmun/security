export const isValidEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/; // Basic email pattern
    return emailRegex.test(email);
};

export const isValidIC = (ic) =>{
    // Regular expression to validate Malaysian IC format: YYMMDD-SSS3
    // Basic IC pattern (12 digits + hyphen)
    const icPattern = /^\d{6}-\d{2}-\d{4}$/;
    return icPattern.test(ic);
};

export const isPasswordValid = (password) => {
    return password.length >= 6; // Ensure password is at least 6 characters
};

export const arePasswordsMatching = (password, confirmPassword) => {
    return password === confirmPassword; // Check if passwords match
};

