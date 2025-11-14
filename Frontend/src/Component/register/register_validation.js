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
    if (typeof password !== 'string') {
        return false;
    }

    const hasMinLength = password.length >= 8;
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSymbol = /[^A-Za-z0-9]/.test(password);

    return hasMinLength && hasUppercase && hasLowercase && hasNumber && hasSymbol;
};

export const arePasswordsMatching = (password, confirmPassword) => {
    return password === confirmPassword; // Check if passwords match
};
