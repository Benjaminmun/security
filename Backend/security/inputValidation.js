/**
 * Input Validation Module
 * 
 * Purpose: Provides comprehensive input validation and sanitization functions
 * to prevent SQL injection, XSS, and other input-based attacks.
 * 
 * OWASP Coverage:
 * - SQL Injection Prevention (parameterized queries + validation)
 * - Input validation best practices
 * 
 * Author: Security Implementation
 * Date: 2025-11-14
 */

import validator from 'validator';

/**
 * Validates and sanitizes email input
 * Prevents SQL injection through email field
 * @param {string} email - Email address to validate
 * @returns {object} - {isValid: boolean, sanitized: string, error: string}
 */
export const validateEmail = (email) => {
    // Check if email is a string
    if (typeof email !== 'string') {
        return { isValid: false, sanitized: '', error: 'Email must be a string' };
    }

    // Trim whitespace
    const trimmed = email.trim();

    // Check length constraints (prevent buffer overflow attempts)
    if (trimmed.length === 0) {
        return { isValid: false, sanitized: '', error: 'Email cannot be empty' };
    }
    
    if (trimmed.length > 254) { // RFC 5321
        return { isValid: false, sanitized: '', error: 'Email too long' };
    }

    // SECURITY: Check for SQL injection patterns FIRST before email validation
    // This ensures SQL injection attempts are properly identified and logged
    const sqlInjectionPatterns = /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b|--|;|\/\*|\*\/|xp_|sp_|'|")/gi;
    if (sqlInjectionPatterns.test(trimmed)) {
        return { isValid: false, sanitized: '', error: 'Invalid characters detected - SQL injection attempt' };
    }

    // Validate email format using validator library
    if (!validator.isEmail(trimmed)) {
        return { isValid: false, sanitized: '', error: 'Invalid email format' };
    }

    // Normalize email (lowercase, remove dangerous characters)
    const sanitized = validator.normalizeEmail(trimmed, {
        gmail_remove_dots: false,
        gmail_remove_subaddress: false,
        outlookdotcom_remove_subaddress: false,
        yahoo_remove_subaddress: false,
        icloud_remove_subaddress: false
    });

    return { isValid: true, sanitized, error: null };
};

/**
 * Validates and sanitizes IC (Identity Card) number
 * Malaysian IC format: YYMMDD-PB-###G
 * @param {string} ic - IC number to validate
 * @returns {object} - {isValid: boolean, sanitized: string, error: string}
 */
export const validateIC = (ic) => {
    if (typeof ic !== 'string') {
        return { isValid: false, sanitized: '', error: 'IC must be a string' };
    }

    const trimmed = ic.trim();

    // Check length constraints
    if (trimmed.length === 0) {
        return { isValid: false, sanitized: '', error: 'IC cannot be empty' };
    }

    if (trimmed.length > 50) {
        return { isValid: false, sanitized: '', error: 'IC too long' };
    }

    // SECURITY: Check for SQL injection patterns FIRST
    const sqlInjectionPatterns = /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b|--|;|\/\*|\*\/|xp_|sp_|<|>|&|'|")/gi;
    if (sqlInjectionPatterns.test(trimmed)) {
        return { isValid: false, sanitized: '', error: 'Invalid characters in IC - SQL injection attempt' };
    }

    // Allow only alphanumeric and hyphens for IC
    if (!/^[0-9\-]+$/.test(trimmed)) {
        return { isValid: false, sanitized: '', error: 'IC must contain only numbers and hyphens' };
    }

    // Malaysian IC format validation (flexible)
    // Format: YYMMDD-PB-###G or variations
    const icPattern = /^\d{6}-?\d{2}-?\d{4}$/;
    if (!icPattern.test(trimmed)) {
        return { isValid: false, sanitized: '', error: 'IC format must be YYMMDD-PB-###G' };
    }

    return { isValid: true, sanitized: trimmed, error: null };
};

/**
 * Validates username
 * Prevents SQL injection and XSS through username field
 * @param {string} username - Username to validate
 * @returns {object} - {isValid: boolean, sanitized: string, error: string}
 */
export const validateUsername = (username) => {
    if (typeof username !== 'string') {
        return { isValid: false, sanitized: '', error: 'Username must be a string' };
    }

    const trimmed = username.trim();

    // Check length constraints
    if (trimmed.length < 3) {
        return { isValid: false, sanitized: '', error: 'Username must be at least 3 characters' };
    }

    if (trimmed.length > 50) {
        return { isValid: false, sanitized: '', error: 'Username too long (max 50 characters)' };
    }

    // SECURITY: Check for SQL injection patterns FIRST
    const sqlInjectionPatterns = /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b|--|;|\/\*|\*\/|xp_|sp_|'|")/gi;
    if (sqlInjectionPatterns.test(trimmed)) {
        return { isValid: false, sanitized: '', error: 'Invalid characters in username - SQL injection attempt' };
    }

    // Allow only alphanumeric and underscores
    if (!/^[a-zA-Z0-9_]+$/.test(trimmed)) {
        return { isValid: false, sanitized: '', error: 'Username can only contain letters, numbers, and underscores' };
    }

    return { isValid: true, sanitized: trimmed, error: null };
};

/**
 * Validates password strength
 * Already exists in Server.js but enhanced here
 * @param {string} password - Password to validate
 * @returns {object} - {isValid: boolean, error: string}
 */
export const validatePassword = (password) => {
    if (typeof password !== 'string') {
        return { isValid: false, error: 'Password must be a string' };
    }

    // Minimum length check
    if (password.length < 8) {
        return { isValid: false, error: 'Password must be at least 8 characters long' };
    }

    // Maximum length check (prevent DoS)
    if (password.length > 128) {
        return { isValid: false, error: 'Password too long (max 128 characters)' };
    }

    // Complexity checks
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSymbol = /[^A-Za-z0-9]/.test(password);

    if (!hasUppercase || !hasLowercase || !hasNumber || !hasSymbol) {
        return { 
            isValid: false, 
            error: 'Password must contain uppercase, lowercase, number, and symbol' 
        };
    }

    return { isValid: true, error: null };
};

/**
 * Validates numeric ID (prevents SQL injection through ID fields)
 * @param {any} id - ID to validate
 * @returns {object} - {isValid: boolean, sanitized: number, error: string}
 */
export const validateNumericId = (id) => {
    // Convert to number
    const numId = Number(id);

    // Check if valid number
    if (isNaN(numId) || !Number.isInteger(numId)) {
        return { isValid: false, sanitized: null, error: 'ID must be a valid integer' };
    }

    // Check positive
    if (numId <= 0) {
        return { isValid: false, sanitized: null, error: 'ID must be positive' };
    }

    // Check reasonable range (prevent overflow)
    if (numId > Number.MAX_SAFE_INTEGER) {
        return { isValid: false, sanitized: null, error: 'ID value too large' };
    }

    return { isValid: true, sanitized: numId, error: null };
};

/**
 * Validates latitude coordinate
 * @param {any} lat - Latitude to validate
 * @returns {object} - {isValid: boolean, sanitized: number, error: string}
 */
export const validateLatitude = (lat) => {
    const numLat = Number(lat);

    if (isNaN(numLat)) {
        return { isValid: false, sanitized: null, error: 'Latitude must be a number' };
    }

    if (numLat < -90 || numLat > 90) {
        return { isValid: false, sanitized: null, error: 'Latitude must be between -90 and 90' };
    }

    return { isValid: true, sanitized: numLat, error: null };
};

/**
 * Validates longitude coordinate
 * @param {any} lng - Longitude to validate
 * @returns {object} - {isValid: boolean, sanitized: number, error: string}
 */
export const validateLongitude = (lng) => {
    const numLng = Number(lng);

    if (isNaN(numLng)) {
        return { isValid: false, sanitized: null, error: 'Longitude must be a number' };
    }

    if (numLng < -180 || numLng > 180) {
        return { isValid: false, sanitized: null, error: 'Longitude must be between -180 and 180' };
    }

    return { isValid: true, sanitized: numLng, error: null };
};

/**
 * Validates status field (enum validation)
 * @param {string} status - Status to validate
 * @returns {object} - {isValid: boolean, sanitized: string, error: string}
 */
export const validateStatus = (status) => {
    if (typeof status !== 'string') {
        return { isValid: false, sanitized: '', error: 'Status must be a string' };
    }

    const trimmed = status.trim().toUpperCase();
    
    // Whitelist of allowed status values
    const allowedStatuses = ['GREEN', 'YELLOW', 'RED', 'PENDING'];

    if (!allowedStatuses.includes(trimmed)) {
        return { isValid: false, sanitized: '', error: 'Invalid status value' };
    }

    return { isValid: true, sanitized: trimmed, error: null };
};

/**
 * Validates and sanitizes text fields (reason, address, etc.)
 * @param {string} text - Text to validate
 * @param {number} maxLength - Maximum allowed length
 * @returns {object} - {isValid: boolean, sanitized: string, error: string}
 */
export const validateText = (text, maxLength = 500) => {
    if (typeof text !== 'string') {
        return { isValid: false, sanitized: '', error: 'Text must be a string' };
    }

    const trimmed = text.trim();

    if (trimmed.length > maxLength) {
        return { isValid: false, sanitized: '', error: `Text too long (max ${maxLength} characters)` };
    }

    // SECURITY: Check for SQL injection patterns
    const sqlInjectionPatterns = /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b|--|\/\*|\*\/|xp_|sp_|'|")/gi;
    if (sqlInjectionPatterns.test(trimmed)) {
        return { isValid: false, sanitized: '', error: 'Invalid characters detected - SQL injection attempt' };
    }

    // Escape HTML to prevent XSS
    const sanitized = validator.escape(trimmed);

    return { isValid: true, sanitized, error: null };
};

/**
 * Validates user type (Admin or users)
 * @param {string} userType - User type to validate
 * @returns {object} - {isValid: boolean, sanitized: string, error: string}
 */
export const validateUserType = (userType) => {
    if (typeof userType !== 'string') {
        return { isValid: false, sanitized: '', error: 'User type must be a string' };
    }

    const allowedTypes = ['Admin', 'users'];
    
    if (!allowedTypes.includes(userType)) {
        return { isValid: false, sanitized: '', error: 'Invalid user type' };
    }

    return { isValid: true, sanitized: userType, error: null };
};

/**
 * Validates base64 image data
 * Prevents injection through image upload
 * @param {string} base64Data - Base64 image data
 * @returns {object} - {isValid: boolean, error: string}
 */
export const validateBase64Image = (base64Data) => {
    if (typeof base64Data !== 'string') {
        return { isValid: false, error: 'Image data must be a string' };
    }

    // Check if it's valid base64
    if (!validator.isBase64(base64Data)) {
        return { isValid: false, error: 'Invalid base64 image data' };
    }

    // Check size limit (10MB limit for base64 string)
    if (base64Data.length > 13421772) { // 10MB in base64
        return { isValid: false, error: 'Image too large (max 10MB)' };
    }

    return { isValid: true, error: null };
};
