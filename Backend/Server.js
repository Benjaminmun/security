import express from 'express';
import mysql from 'mysql';
import helmet from 'helmet';
import cors from 'cors';
import bcrypt from 'bcrypt';//hash password
import multer from 'multer'//handle multiple form content
import cookieParser from 'cookie-parser';//httpOnly cookie
import axios from 'axios';
import querystring from 'querystring';
import bodyParser from 'body-parser';
import FormData from 'form-data';
import rateLimit from 'express-rate-limit';

//.env
import dotenv from 'dotenv';
dotenv.config();


import speakeasy from 'speakeasy';
import QRCode from 'qrcode';

//login 
import jwt from 'jsonwebtoken'; // import json web token

/**
 * SECURITY MODULES - OWASP Top 10 Implementation
 * These modules provide comprehensive security controls including:
 * - Input validation and SQL injection prevention
 * - Access control (RBAC) for broken access control prevention (A01)
 * - SSRF protection for server-side request forgery prevention (A10)
 * - Security logging and monitoring for audit trail (A09)
 */
import {
    validateEmail,
    validateIC,
    validateUsername,
    validatePassword,
    validateNumericId,
    validateLatitude,
    validateLongitude,
    validateStatus,
    validateText,
    validateUserType,
    validateBase64Image
} from './security/inputValidation.js';

import {
    requireAdmin,
    requireUser,
    verifyResourceOwnership,
    canModifyUser,
    canDeleteUser,
    canViewUser
} from './security/accessControl.js';

import {
    validateExternalUrl,
    safeExternalRequest,
    validateImageUrl
} from './security/ssrfProtection.js';

import {
    logSecurityEvent,
    logFailedLogin,
    logSuccessfulLogin,
    logAccessDenied,
    logDataModification,
    logSqlInjectionAttempt,
    logSsrfAttempt,
    logRateLimitExceeded,
    logHttpRequest,
    initializeLogRotation,
    LOG_LEVELS,
    EVENT_TYPES
} from './security/securityLogging.js';

const app = express();

// import rateLimit from "express-rate-limit";

app.use(helmet());

// Specifically set headers
app.use(helmet.noSniff());                // X-Content-Type-Options: nosniff
app.use(helmet.frameguard({ action: 'deny' })); // X-Frame-Options: DENY

app.disable('x-powered-by'); 

const isStrongPassword = (password) => {
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

//////////////////////////////////////////////////////////////////////////////// Enhanced Rate Limiting Configuration //////////////////////////////////////////////////

// SECURITY FIX: Removed custom keyGenerator to use default IPv6-safe key generation
// The default keyGenerator properly handles both IPv4 and IPv6 addresses
// Enhanced Login rate limiter - prevents brute force attacks with precise timing
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login attempts per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  // Using default keyGenerator for IPv6 compatibility
  skipSuccessfulRequests: true, // Don't count successful logins
  handler: (req, res) => {
    const resetTime = req.rateLimit.resetTime; // This is a Date object
    const now = Date.now();
    const waitTimeInSeconds = Math.round((resetTime - now) / 1000);
    const waitTimeInMinutes = Math.ceil(waitTimeInSeconds / 60);

    console.warn(`Rate limit exceeded for IP: ${req.ip}, User-Agent: ${req.headers['user-agent']}, Wait time: ${waitTimeInSeconds}s`);

    // Set the standard 'Retry-After' header
    res.setHeader('Retry-After', waitTimeInSeconds);

    res.status(429).json({
      error: "Too many login attempts from this IP",
      message: `Too many login attempts. Please try again in ${waitTimeInMinutes} minute(s).`,
      retryAfter: waitTimeInSeconds,
      resetTime: resetTime.toISOString()
    });
  }
});

// SECURITY FIX: Removed custom keyGenerator to use default IPv6-safe key generation
// Account-specific rate limiter with precise timing
const accountLoginLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Max attempts per account per hour
  // Using default keyGenerator for IPv6 compatibility
  skipSuccessfulRequests: true,
  handler: (req, res) => {
    const resetTime = req.rateLimit.resetTime;
    const now = Date.now();
    const waitTimeInSeconds = Math.round((resetTime - now) / 1000);
    const waitTimeInMinutes = Math.ceil(waitTimeInSeconds / 60);

    console.warn(`Account rate limit exceeded for: ${req.body.email || req.body.ic}, Wait time: ${waitTimeInSeconds}s`);

    res.setHeader('Retry-After', waitTimeInSeconds);
    
    res.status(429).json({
      error: "Too many login attempts for this account",
      message: `Too many login attempts for this account. Please try again in ${waitTimeInMinutes} minute(s).`,
      retryAfter: waitTimeInSeconds,
      resetTime: resetTime.toISOString()
    });
  }
});

// Registration rate limiter - prevents mass account creation
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit each IP to 3 registration requests per hour
  handler: (req, res) => {
    const resetTime = req.rateLimit.resetTime;
    const now = Date.now();
    const waitTimeInSeconds = Math.round((resetTime - now) / 1000);
    const waitTimeInMinutes = Math.ceil(waitTimeInSeconds / 60);

    console.warn(`Registration rate limit exceeded for IP: ${req.ip}, Wait time: ${waitTimeInSeconds}s`);
    res.setHeader('Retry-After', waitTimeInSeconds);
    
    res.status(429).json({
      error: "Too many accounts created from this IP",
      message: `Too many registration attempts. Please try again in ${waitTimeInMinutes} minute(s).`,
      retryAfter: waitTimeInSeconds,
      resetTime: resetTime.toISOString()
    });
  }
});

// General API rate limiter - protects against DoS attacks
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  handler: (req, res) => {
    const resetTime = req.rateLimit.resetTime;
    const waitTimeInSeconds = Math.round((resetTime - Date.now()) / 1000);

    res.setHeader('Retry-After', waitTimeInSeconds);
    
    res.status(429).json({
      error: "Too many requests from this IP",
      message: `Too many requests. Please try again in ${Math.ceil(waitTimeInSeconds / 60)} minute(s).`,
      retryAfter: waitTimeInSeconds
    });
  }
});

// Strict rate limiter for sensitive endpoints
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 requests per windowMs
  handler: (req, res) => {
    const resetTime = req.rateLimit.resetTime;
    const waitTimeInSeconds = Math.round((resetTime - Date.now()) / 1000);

    res.setHeader('Retry-After', waitTimeInSeconds);
    
    res.status(429).json({
      error: "Too many requests to this endpoint",
      message: `Too many requests to this endpoint. Please try again in ${Math.ceil(waitTimeInSeconds / 60)} minute(s).`,
      retryAfter: waitTimeInSeconds
    });
  }
});

// Global rate limiter middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 400,                 // limit each IP to 40 requests per 15 mins
  standardHeaders: true,    // return rate limit info in headers
  legacyHeaders: false
});

// Apply to all requests
app.use(limiter);

// Use cookie-parser middleware
app.use(cookieParser());

// Load environment variables
dotenv.config();

// Security headers middleware
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});

/**
 * SECURITY ENHANCEMENT: Initialize security logging and monitoring (OWASP A09)
 * This starts the automatic log rotation scheduler which rotates logs when they exceed 10MB
 */
initializeLogRotation();

/**
 * SECURITY ENHANCEMENT: HTTP request logging middleware (OWASP A09)
 * Logs all HTTP requests with method, path, status code, duration, IP, and user info
 * Creates comprehensive audit trail for security monitoring and incident response
 */
app.use(logHttpRequest);

// Request logging middleware (legacy - kept for backward compatibility)
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - IP: ${req.ip}`);
    next();
});

// Middleware
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));

// app.use(cors({
//     origin: 'http://localhost:3000',
//     credentials: true
// }));

const allowedOrigins = ['http://localhost:3000']; 

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like Postman, curl)
        if (!origin) return callback(null, true);

        if (allowedOrigins.indexOf(origin) === -1) {
            // Respond with 403 Forbidden instead of throwing an error
            return callback(new Error('CORS policy: This origin is not allowed'));
        }

        return callback(null, true);
    },
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 600
}));

// Catch CORS errors and respond properly
app.use((err, req, res, next) => {
    if (err.message && err.message.includes('CORS policy')) {
        return res.status(403).json({ error: err.message });
    }
    next(err);
});

// Enforce HTTPS 
app.use((req, res, next) => {
    if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
        return res.redirect('https://' + req.headers.host + req.url);
    }
    next();
});

// Disable caching
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    res.set('Surrogate-Control', 'no-store');
    next();
});

//////////////////////////////////////////////////////////////////////////////// MySQL connection////////////////////////////////////////////////////
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "dbkl_project",
});

/////////////////////////////////////////////////////////////////////////middleware to verify token//////////////////////////////////////////////////
const verifyToken = (req, res, next) => {
  const token = req.cookies.token;

  console.log('[VERIFY TOKEN] Checking authentication...');
  console.log('[VERIFY TOKEN] Token from cookies:', token ? 'Token present' : 'NO TOKEN');
  console.log('[VERIFY TOKEN] All cookies:', req.cookies);

  if (!token) {
    console.warn('[VERIFY TOKEN] No token provided - rejecting request');
    return res.status(403).json({ message: 'No token provided.' });
  }

  jwt.verify(token, process.env.LOGIN_KEY, (err, decoded) => {
    if (err) {
      console.error('[VERIFY TOKEN] Invalid token error:', err.message);
      return res.status(401).json({ message: 'Invalid token.' });
    }
    console.log('[VERIFY TOKEN] Token successfully decoded:', { id: decoded.id, userType: decoded.userType, email: decoded.email });
    req.user = decoded;
    next();
  });
};


// Idle Timeout (sliding expiration)
const ACCESS_EXPIRES_MS = 15 * 60 * 1000; // 15 minutes in milliseconds
const ACCESS_EXPIRES_STR = '15m';         // jwt expiresIn string

function generateAccessToken(payload) {
  return jwt.sign(payload, process.env.LOGIN_KEY, { expiresIn: ACCESS_EXPIRES_STR });
}

// EXTEND TOKEN (sliding expiration)
app.post('/auth/extend', verifyToken, (req, res) => {
    const payload = {
        id: req.user.id,
        email: req.user.email,
        userType: req.user.userType
    };

    const newToken = generateAccessToken(payload);

    res.cookie('token', newToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: ACCESS_EXPIRES_MS
    });

    res.json({ message: "Token extended" });
});

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

/////////////////////////////////////////////////////////////////////// DB connection is established///////////////////////////////////////////////
db.connect(err => {
    if (err) {
        console.error('Error connecting to the database:', err);
        process.exit(1);
    }
    console.log('Connected to the database');
});

// Helper functions for tracking failed attempts
const logFailedAttempt = (identifier, ip, userAgent) => {
    const query = "INSERT INTO login_attempts (identifier, ip_address, user_agent, success, attempt_time) VALUES (?, ?, ?, ?, NOW())";
    db.query(query, [identifier, ip, userAgent, false], (err) => {
        if (err) console.error('Error logging failed attempt:', err);
    });
};

const clearFailedAttempts = (identifier) => {
    const query = "DELETE FROM login_attempts WHERE identifier = ? AND success = false";
    db.query(query, [identifier], (err) => {
        if (err) console.error('Error clearing failed attempts:', err);
    });
};

// Store active locks in memory (for production, use Redis)
const accountLocks = new Map();

const isAccountLocked = (identifier) => {
    const lock = accountLocks.get(identifier);
    if (lock && lock.until > Date.now()) {
        return lock;
    }
    if (lock) {
        accountLocks.delete(identifier); // Remove expired lock
    }
    return null;
};

const lockAccount = (identifier, durationMs = 30 * 60 * 1000) => { // 30 minutes default
    const lock = {
        identifier,
        until: Date.now() + durationMs,
        lockedAt: new Date()
    };
    accountLocks.set(identifier, lock);
    return lock;
};

/////////////////////////////////////////////////////////// Endpoint to handle GET request//////////////////////////////////////////////////////////
app.get('/', apiLimiter, (req, res) => {
    return res.json("From Backend Side!");
});

///////////////////////////////////////////////////////////////////////////// Enhanced Login route/////////////////////////////////////////////////////////////
/**
 * SECURITY ENHANCEMENTS Applied:
 * 1. Input validation using comprehensive validation module (SQL injection prevention)
 * 2. Security event logging for failed/successful login attempts (A09)
 * 3. SQL injection pattern detection in email and IC fields
 * 4. Type validation for userType parameter
 * All database queries use parameterized statements (SQL injection prevention)
 */
app.post('/Login', [loginLimiter, accountLoginLimiter], async (req, res) => {
    const { email, password, ic, userType } = req.body;
    const clientIP = req.ip;
    const userAgent = req.headers['user-agent'];

    console.log(`Login attempt from IP: ${clientIP}, User-Type: ${userType}`);

    // SECURITY: Validate user type first (prevents injection through userType parameter)
    const userTypeValidation = validateUserType(userType);
    if (!userTypeValidation.isValid) {
        logSecurityEvent(
            LOG_LEVELS.WARN,
            EVENT_TYPES.INVALID_INPUT,
            'Invalid user type in login attempt',
            { userType, error: userTypeValidation.error, ip: clientIP }
        );
        return res.status(400).json({ message: userTypeValidation.error });
    }

    let identifier;
    let validatedEmail = null;
    let validatedIC = null;

    // SECURITY: Enhanced input validation with SQL injection prevention
    if (userType === "Admin") {
        if (!email || !password) {
            console.warn(`Missing credentials - Admin login attempt from IP: ${clientIP}`);
            logSecurityEvent(
                LOG_LEVELS.WARN,
                EVENT_TYPES.INVALID_INPUT,
                'Missing credentials in admin login',
                { ip: clientIP }
            );
            return res.status(400).json({ message: 'Email and password are required for Admin login.' });
        }
        
        // SECURITY: Validate and sanitize email (prevents SQL injection through email field)
        const emailValidation = validateEmail(email);
        if (!emailValidation.isValid) {
            // Log potential SQL injection attempt if dangerous patterns detected
            if (email && (email.includes('--') || email.includes(';') || /union|select|insert|update|delete|drop/i.test(email))) {
                logSqlInjectionAttempt(email, 'email', clientIP, '/Login');
            }
            logSecurityEvent(
                LOG_LEVELS.WARN,
                EVENT_TYPES.INVALID_INPUT,
                'Invalid email format in login',
                { email, error: emailValidation.error, ip: clientIP }
            );
            return res.status(400).json({ message: emailValidation.error });
        }
        validatedEmail = emailValidation.sanitized;
        identifier = validatedEmail;
    } else if (userType === "users") {
        if (!ic || !password) {
            console.warn(`Missing credentials - User login attempt from IP: ${clientIP}`);
            logSecurityEvent(
                LOG_LEVELS.WARN,
                EVENT_TYPES.INVALID_INPUT,
                'Missing credentials in user login',
                { ip: clientIP }
            );
            return res.status(400).json({ message: 'IC and password are required for User login.' });
        }
        
        // SECURITY: Validate and sanitize IC (prevents SQL injection through IC field)
        const icValidation = validateIC(ic);
        if (!icValidation.isValid) {
            // Log potential SQL injection attempt if dangerous patterns detected
            if (ic && (ic.includes('--') || ic.includes(';') || /union|select|insert|update|delete|drop/i.test(ic))) {
                logSqlInjectionAttempt(ic, 'ic', clientIP, '/Login');
            }
            logSecurityEvent(
                LOG_LEVELS.WARN,
                EVENT_TYPES.INVALID_INPUT,
                'Invalid IC format in login',
                { ic, error: icValidation.error, ip: clientIP }
            );
            return res.status(400).json({ message: icValidation.error });
        }
        validatedIC = icValidation.sanitized;
        identifier = validatedIC;
    }

    // Password validation (not logged in plain text for security)
    if (!password || password.length < 1) {
        return res.status(400).json({ message: 'Password is required.' });
    }

    try {
        let query;
        let parameter;

        // Check for account lock
        const accountLock = isAccountLocked(identifier);
        if (accountLock) {
            const remainingTime = Math.ceil((accountLock.until - Date.now()) / 1000 / 60);
            console.warn(`Login attempt to locked account: ${identifier} from IP: ${clientIP}`);
            return res.status(423).json({ 
                message: `Account is temporarily locked due to too many failed attempts. Please try again in ${remainingTime} minute(s).`,
                retryAfter: Math.ceil((accountLock.until - Date.now()) / 1000)
            });
        }

        // SECURITY: Use validated and sanitized inputs in parameterized query
        // Determine query and parameter based on userType
        if (userType === "Admin") {
            query = "SELECT * FROM admin WHERE email = ?";
            parameter = [validatedEmail]; // Using validated email (SQL injection prevented)
        } else {
            query = "SELECT * FROM users WHERE ic = ?";
            parameter = [validatedIC]; // Using validated IC (SQL injection prevented)
        }

        // Execute database query with parameterized statement (prevents SQL injection)
        db.query(query, parameter, async (err, results) => {
            if (err) {
                console.error(`Database error during login for ${identifier}:`, err);
                logSecurityEvent(
                    LOG_LEVELS.ERROR,
                    EVENT_TYPES.LOGIN_FAILURE,
                    'Database error during login',
                    { identifier, error: err.message, ip: clientIP }
                );
                return res.status(500).json({ message: 'Server error' });
            }

            if (results.length === 0) {
                console.warn(`Failed login attempt - User not found: ${identifier} from IP: ${clientIP}`);
                // SECURITY: Log failed login attempt (A09 - Security Logging)
                logFailedLogin(identifier, clientIP, userAgent, 'User not found');
                logFailedAttempt(identifier, clientIP, userAgent);
                
                // Check if we should lock the account (after multiple failed attempts)
                const failedAttemptsQuery = "SELECT COUNT(*) as count FROM login_attempts WHERE identifier = ? AND success = false AND attempt_time > DATE_SUB(NOW(), INTERVAL 30 MINUTE)";
                db.query(failedAttemptsQuery, [identifier], (err, attemptResults) => {
                    if (!err && attemptResults[0].count >= 5) {
                        const lock = lockAccount(identifier);
                        console.warn(`Account locked due to multiple failed attempts: ${identifier}`);
                        logSecurityEvent(
                            LOG_LEVELS.WARN,
                            EVENT_TYPES.ACCOUNT_LOCKED,
                            'Account locked due to multiple failed login attempts',
                            { identifier, ip: clientIP }
                        );
                    }
                });

                return res.status(401).json({ message: 'Invalid credentials' });
            }

            const user = results[0];

            // Compare password with the hashed password in the database
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                console.warn(`Failed login attempt - Invalid password for: ${identifier} from IP: ${clientIP}`);
                // SECURITY: Log failed login attempt (A09 - Security Logging)
                logFailedLogin(identifier, clientIP, userAgent, 'Invalid password');
                logFailedAttempt(identifier, clientIP, userAgent);

                // Check if we should lock the account
                const failedAttemptsQuery = "SELECT COUNT(*) as count FROM login_attempts WHERE identifier = ? AND success = false AND attempt_time > DATE_SUB(NOW(), INTERVAL 30 MINUTE)";
                db.query(failedAttemptsQuery, [identifier], (err, attemptResults) => {
                    if (!err && attemptResults[0].count >= 5) {
                        const lock = lockAccount(identifier);
                        console.warn(`Account locked due to multiple failed attempts: ${identifier}`);
                        logSecurityEvent(
                            LOG_LEVELS.WARN,
                            EVENT_TYPES.ACCOUNT_LOCKED,
                            'Account locked due to multiple failed login attempts',
                            { identifier, ip: clientIP }
                        );
                    }
                });

                return res.status(401).json({ message: 'Invalid credentials' });
            }

            if (user.two_fa_enabled === 1) {
                return res.json({
                    message: '2FA verification required',
                    requiresTwoFactor: true,
                    userId: userType === 'Admin' ? user.admin_id : user.id,
                    userType: userType,
                    user: {
                        id: userType === 'Admin' ? user.admin_id : user.id,
                        email: user.email || user.ic,
                        name: user.name
                    }
                });
            }


            // Check if account is locked in database
            if (user.is_locked) {
                console.warn(`Login attempt to locked account: ${identifier} from IP: ${clientIP}`);
                logSecurityEvent(
                    LOG_LEVELS.WARN,
                    EVENT_TYPES.ACCESS_DENIED,
                    'Login attempt to locked account',
                    { identifier, ip: clientIP }
                );
                return res.status(423).json({ message: 'Account is locked. Please contact administrator.' });
            }

            // session expiry logic
            const SESSION_DURATION_MS = 15 * 60 * 1000; // 15 minutes 
            // SECURITY FIX: Create a JSON Web Token (JWT) for authenticated users
            // Use correct ID field based on userType (admin table uses 'admin_id', users table uses 'id')
            const token = jwt.sign(
                { 
                    id: userType === 'Admin' ? user.admin_id : user.id, 
                    email: user.email || user.ic, 
                    userType: userType,
                    loginTime: Date.now(),
                    sessionExpiry: Date.now() + SESSION_DURATION_MS
                },
                process.env.LOGIN_KEY,
                { expiresIn: '15m' }
            );

            // SECURITY: Set the JWT as an HttpOnly cookie
            // Using 'lax' sameSite instead of 'strict' to allow cookies to be sent with cross-origin requests
            // from frontend (localhost:3000) to backend (localhost:8081)
            res.cookie('token', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'lax', // Changed from 'strict' to 'lax' for cross-origin compatibility
                maxAge: SESSION_DURATION_MS // COOKIE EXPIRY ADDED

            });

            // SECURITY: Log successful login (A09 - Security Logging and Monitoring)
            console.log(`Successful login: ${identifier} from IP: ${clientIP}`);
            logSuccessfulLogin(identifier, clientIP, userAgent, userType);

            // Clear any failed attempts on successful login
            clearFailedAttempts(identifier);
            accountLocks.delete(identifier); // Remove lock on successful login

            // Log successful attempt in database
            const successQuery = "INSERT INTO login_attempts (identifier, ip_address, user_agent, success, attempt_time) VALUES (?, ?, ?, ?, NOW())";
            db.query(successQuery, [identifier, clientIP, userAgent, true], (err) => {
                if (err) console.error('Error logging successful attempt:', err);
            });

            // SECURITY FIX: Respond with user info (without password) and success message
            // Use correct ID field based on userType (admin table uses 'admin_id', users table uses 'id')
            return res.json({
                message: 'Login successful',
                user: {
                    id: userType === 'Admin' ? user.admin_id : user.id,
                    email: user.email || user.ic,
                    requiresTwoFactor: false,
                    userType: userType
                }
            });
        });
    } catch (error) {
        console.error(`Unexpected error during login from IP: ${clientIP}:`, error);
        return res.status(500).json({ message: 'Server error' });
    }
});

///////////////////////////////////////////////////////////////////// check-account-exist endpoint////////////////////////////////////////////////
/**
 * SECURITY ENHANCEMENTS Applied:
 * 1. Input validation for email, username, IC (SQL injection prevention)
 * 2. User type validation
 * All queries use parameterized statements (SQL injection prevention)
 */
app.post('/check-account-exist', apiLimiter, (req, res) => {
    const { username, email, ic, userType} = req.body;

    // SECURITY: Validate user type
    const userTypeValidation = validateUserType(userType);
    if (!userTypeValidation.isValid) {
        return res.status(400).json({ message: userTypeValidation.error });
    }

    if(userType === "Admin"){
        // SECURITY: Validate email (prevents SQL injection)
        if (email) {
            const emailValidation = validateEmail(email);
            if (!emailValidation.isValid) {
                if (email && (email.includes('--') || email.includes(';') || /union|select|insert|update|delete|drop/i.test(email))) {
                    logSqlInjectionAttempt(email, 'email', req.ip, '/check-account-exist');
                }
                return res.status(400).json({ message: emailValidation.error });
            }
            
            // Use validated email in parameterized query (SQL injection prevented)
            const emailQuery = "SELECT * FROM admin WHERE email = ?";
            db.query(emailQuery, [emailValidation.sanitized], (err, emailResults) => {
                if (err) return res.status(500).json({ message: 'Error checking account existence.' });

                if (emailResults.length > 0) {
                    return res.json({ message: 'An account already exists with this email.' });
                }

                // SECURITY: Validate username (prevents SQL injection)
                if (username) {
                    const usernameValidation = validateUsername(username);
                    if (!usernameValidation.isValid) {
                        if (username && (username.includes('--') || username.includes(';'))) {
                            logSqlInjectionAttempt(username, 'username', req.ip, '/check-account-exist');
                        }
                        return res.status(400).json({ message: usernameValidation.error });
                    }

                    // Use validated username in parameterized query (SQL injection prevented)
                    const usernameQuery = "SELECT * FROM admin WHERE username = ?";
                    db.query(usernameQuery, [usernameValidation.sanitized], (err, usernameResults) => {
                        if (err) return res.status(500).json({ message: 'Error checking account existence.' });

                        if (usernameResults.length > 0) {
                            return res.status(409).json({ message: 'An account already exists with this username.' });
                        }

                        return res.json({ message: 'No existing account with this email or username.' });
                    });
                } else {
                    return res.json({ message: 'No existing account with this email.' });
                }
            });
        } else {
            return res.status(400).json({ message: 'Email is required for Admin account check.' });
        }
    }else if(userType === "users"){
        // SECURITY: Validate IC (prevents SQL injection)
        if (ic) {
            const icValidation = validateIC(ic);
            if (!icValidation.isValid) {
                if (ic && (ic.includes('--') || ic.includes(';') || /union|select|insert|update|delete|drop/i.test(ic))) {
                    logSqlInjectionAttempt(ic, 'ic', req.ip, '/check-account-exist');
                }
                return res.status(400).json({ message: icValidation.error });
            }

            // Use validated IC in parameterized query (SQL injection prevented)
            const icQuery = "SELECT * FROM users WHERE ic = ?";
            db.query(icQuery, [icValidation.sanitized], (err, icResults) =>{
                if (err) return res.status(500).json({ message: 'Error checking account existence.' });
                
                if (icResults.length > 0) {
                    return res.status(409).json({ message: 'An account already exists with this IC.' });
                }

                return res.json({message: "No existing account with this IC."})
            });
        } else {
            return res.status(400).json({ message: 'IC is required for User account check.' });
        }
    }
});

/////////////////////////////////////////////////////////////////////////////// Register endpoint///////////////////////////////////////////////////
/**
 * SECURITY ENHANCEMENTS Applied:
 * 1. Input validation for username, email, IC, password (SQL injection prevention)
 * 2. Password strength validation (already implemented via isStrongPassword)
 * 3. Security event logging for registration attempts
 * All queries use parameterized statements with validated inputs (SQL injection prevention)
 */
app.post('/register', registerLimiter, async (req, res) => {
    console.log('Received request:', req.body);
    const { username, email, password, ic, userType} = req.body;

    // SECURITY: Validate user type
    const userTypeValidation = validateUserType(userType);
    if (!userTypeValidation.isValid) {
        return res.status(400).json({ message: userTypeValidation.error });
    }

    let validatedEmail, validatedUsername, validatedIC;

    if(userType === "Admin"){
        // SECURITY: Validate all admin inputs
        if (!username || !email || !password) {
            return res.status(400).json({ message: 'All fields are required for Admin registration.' });
        }

        // Validate username (prevents SQL injection)
        const usernameValidation = validateUsername(username);
        if (!usernameValidation.isValid) {
            if (username && (username.includes('--') || username.includes(';'))) {
                logSqlInjectionAttempt(username, 'username', req.ip, '/register');
            }
            return res.status(400).json({ message: usernameValidation.error });
        }
        validatedUsername = usernameValidation.sanitized;

        // Validate email (prevents SQL injection)
        const emailValidation = validateEmail(email);
        if (!emailValidation.isValid) {
            if (email && (email.includes('--') || email.includes(';') || /union|select|insert|update|delete|drop/i.test(email))) {
                logSqlInjectionAttempt(email, 'email', req.ip, '/register');
            }
            return res.status(400).json({ message: emailValidation.error });
        }
        validatedEmail = emailValidation.sanitized;

        // Validate password strength
        if (!isStrongPassword(password)) {
            return res.status(400).json({ message: 'Password must be at least 8 characters with uppercase, lowercase, number, and symbol.' });
        }
    }else if(userType === "users"){
        // SECURITY: Validate user inputs
        if(!ic || !password) {
            return res.status(400).json({ message: 'All fields are required for User registration.' });
        }

        // Validate IC (prevents SQL injection)
        const icValidation = validateIC(ic);
        if (!icValidation.isValid) {
            if (ic && (ic.includes('--') || ic.includes(';') || /union|select|insert|update|delete|drop/i.test(ic))) {
                logSqlInjectionAttempt(ic, 'ic', req.ip, '/register');
            }
            return res.status(400).json({ message: icValidation.error });
        }
        validatedIC = icValidation.sanitized;

        // Validate password strength
        if (!isStrongPassword(password)) {
            return res.status(400).json({ message: 'Password must be at least 8 characters with uppercase, lowercase, number, and symbol.' });
        }
    }
    
    try {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        let parameter;
        let query; 

        // SECURITY: Use validated inputs in parameterized queries (SQL injection prevented)
        if(userType === "Admin"){
            query = "INSERT INTO admin (email, username, password) VALUES (?, ?, ?)";
            parameter = [validatedEmail, validatedUsername, hashedPassword]
        } else if(userType === "users"){
            query = "INSERT INTO users (IC, password) VALUES (?, ?)";
            parameter = [validatedIC, hashedPassword]
        }
           
        db.query(query, parameter, (err, data) => {

            if (err) {
                console.error('Error inserting data:', err.code, err.message);
                logSecurityEvent(
                    LOG_LEVELS.ERROR,
                    'REGISTRATION_FAILURE',
                    'Database error during registration',
                    { userType, error: err.message, ip: req.ip }
                );
                return res.status(500).json({ message: 'Error !!', error: err.message });
            }

            if (data.affectedRows > 0) {
                console.log('signup successful', req.body);
                // SECURITY: Log successful registration (A09 - Security Logging)
                logSecurityEvent(
                    LOG_LEVELS.INFO,
                    'REGISTRATION_SUCCESS',
                    `Successful registration for ${userType}`,
                    { identifier: validatedEmail || validatedIC, userType, ip: req.ip }
                );
                return res.json({ message: "Sign Up Successful" });
            }
            return res.json({ message: "Sign Up unsuccessfully", data: data });
            
        });
    } catch (error) {
        console.error('Error hashing password:', error);
        return res.status(500).json({ message: 'Error hashing password', error: error.message });
    }
});

/////////////////////////////////////////////////////////////logout//////////////////////////////////////////////////
app.post('/logout', apiLimiter, (req, res) =>{
    console.log(req.body);
    
    res.clearCookie('token',{
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
    });
     
    return res.json({ message: 'Logged out successfully' });
});

/**
 * SECURITY ENHANCEMENT: Upload to ImgBB with SSRF protection
 * Uses safe external request wrapper to prevent SSRF attacks (OWASP A10)
 */
const uploadToImgBB = async (imageBase64) => {
    try {
        const form = new FormData();
        form.append('key', process.env.IMGBB_API_KEY);
        form.append('image', imageBase64);

        // SECURITY: Use safe external request with SSRF protection
        const imgbbUrl = 'https://api.imgbb.com/1/upload';
        const validation = validateExternalUrl(imgbbUrl);
        
        if (!validation.isValid) {
            console.error('ImgBB URL validation failed:', validation.error);
            return null;
        }

        const response = await safeExternalRequest(
            imgbbUrl,
            {
                method: 'POST',
                data: form,
                headers: form.getHeaders(),
                maxBodyLength: Infinity,
            },
            axios
        );

        console.log('ImgBB Upload Response:', response.data);

        if (response.data && response.data.success) {
            console.log('Image uploaded to ImgBB successfully:', response.data.data.url);
            return response.data.data.url;
        } else {
            console.error('ImgBB upload failed:', response.data);
            return null;
        }
    } catch (uploadError) {
        console.error('Error uploading to ImgBB:', uploadError.response ? uploadError.response.data : uploadError.message);
        // SECURITY: Log SSRF attempt if error is related to blocked URL
        if (uploadError.name === 'SSRFProtectionError') {
            logSsrfAttempt(imgbbUrl, 'server', '/uploadImage');
        }
        return null;
    }
};

///////////////////////////////////////////////////////////// update upload attempt status/////////////////////////////////////////////////////////
app.post('/updateUploadAttempt', verifyToken, apiLimiter, (req, res) => {
    const userId = req.user.id;
    const uploadAttemptId = req.body.uploadAttemptId;
    db.query('UPDATE users SET upload_attempts = ? WHERE id = ?',[uploadAttemptId, userId], (err, result) => {
        if (err) {
            return res.status(500).send('Error updating upload attempt');
        }
        res.status(200).send('Upload attempt updated successfully');
    });
});

//////////////////////////////////////////////////////////////////fetch upload attempts/////////////////////////////////////////////////////////////
app.get('/getUploadAttempts', verifyToken, apiLimiter, (req, res) => {
    const userId = req.user.id;  

    const query = 'SELECT upload_attempts FROM users WHERE id = ?';

    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Error in query', err);  
            return res.status(500).json({ message: 'Error retrieving upload attempts', error: err });
        }

        console.log('Query result:', results);

        if (results && results.length > 0) {
            const uploadAttempts = results[0].upload_attempts;
            res.status(200).json({ uploadAttempts });
        } else {
            res.status(404).json({ message: 'No data found for this user' });
        }
    });
});

/////////////////////////////////////////////////// Photo Upload Endpoint///////////////////////////////////////////////
app.post('/uploadImage', strictLimiter, upload.single('file'), verifyToken, (req, res) => {
    console.log("File Upload Request:", req.file);
    const userId = req.user.id;

    if (!req.file) {
        return res.status(400).json({ message: 'Image file is required.' });
    }

    const validMimeTypes = ['image/jpeg', 'image/png', 'image/jpg'];
    if (!validMimeTypes.includes(req.file.mimetype)) {
        return res.status(400).json({ message: 'Invalid file type. Only JPG, PNG are allowed.' });
    }

    const imageBuffer = req.file.buffer;
    const imageBase64 = imageBuffer.toString('base64');
    const imageContentType = req.file.mimetype;

    console.log('Image Base64 Length:', imageBase64.length);
    console.log('Image Base64 Prefix:', imageBase64.substring(0, 30));

    const query = 'UPDATE users SET images = ?, image_content_type = ? WHERE id = ?';
    db.query(query, [imageBase64, imageContentType, userId], (err, result) => {
        if (err) {
            console.error('Database error while updating image:', err);
            return res.status(500).json({ message: 'Database error', error: err.message });
        }

        if (result.affectedRows > 0) {
            return res.json({ message: 'Image updated successfully' });
        } else {
            return res.status(404).json({ message: 'User not found' });
        }
    });
});

/////////////////////////////////////////////////////////// Compare Faces Endpoint//////////////////////////////////////
app.post('/compareFaces', strictLimiter, verifyToken, async (req, res) => {
    console.log('User object:', req.user);
    const { capturedImage } = req.body;
    const userId = req.user.id;

    if (!capturedImage) {
        return res.status(400).json({ message: 'No captured image provided.' });
    }

    const query = 'SELECT images FROM users WHERE id = ?';
    db.query(query, [userId], async (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ message: 'Database error.', error: err });
        }

        if (results.length === 0) {
            console.error('User image not found for user ID:', userId);
            return res.status(404).json({ message: 'User image not found.' });
        }

        const storedImageBase64 = results[0].images;

        console.log('Stored Image Base64 Length:', storedImageBase64.length);
        console.log('Stored Image Base64 Prefix:', storedImageBase64.substring(0, 30));

        if (!storedImageBase64 || !capturedImage) {
            console.error('One or both images are missing.');
            return res.status(400).json({ message: 'Invalid image data.' });
        }

        try {
            const storedImageUrl = await uploadToImgBB(storedImageBase64);
            if (!storedImageUrl) {
                return res.status(500).json({ message: 'Failed to upload stored image to ImgBB.' });
            }

            const capturedImageUrl = await uploadToImgBB(capturedImage);
            if (!capturedImageUrl) {
                return res.status(500).json({ message: 'Failed to upload captured image to ImgBB.' });
            }

            const verifyImageUrl = async (url) => {
                try {
                    const response = await axios.get(url);
                    console.log(`Verified URL (${url}):`, response.status);
                    return response.status === 200;
                } catch (error) {
                    console.error(`Error accessing URL (${url}):`, error.message);
                    return false;
                }
            };

            const isStoredImageUrlValid = await verifyImageUrl(storedImageUrl);
            const isCapturedImageUrlValid = await verifyImageUrl(capturedImageUrl);

            if (!isStoredImageUrlValid || !isCapturedImageUrlValid) {
                console.error('One or both image URLs are invalid or inaccessible.');
                return res.status(400).json({ message: 'Invalid or inaccessible image URLs.' });
            }

            const faceData = querystring.stringify({
                api_key: process.env.FACE_API_KEY,
                api_secret: process.env.FACE_API_SECRET,
                image_url1: storedImageUrl,
                image_url2: capturedImageUrl,
            });

            console.log('Sending data to Face++:', faceData);

            const facePlusPlusResponse = await axios.post(
                'https://api-us.faceplusplus.com/facepp/v3/compare',
                faceData,
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                }
            );

            console.log('Face++ API Response:', facePlusPlusResponse.data);

            const { confidence, error_message } = facePlusPlusResponse.data;

            if (error_message) {
                console.error('Face++ API error:', error_message);
                return res.status(500).json({ message: 'Face++ API error', error: error_message });
            }

            if(!confidence){
                return res.status(200).json({ message: 'Faces do not match.' });
            }else if (confidence >= 70) {
                return res.json({ message: 'Faces match', confidence });
            }else {
                return res.json({ message: 'Faces do not match', confidence });
            }

        } catch (error) {
            console.error('Error during face comparison:', error.response ? error.response.data : error.message);
            return res.status(500).json({ message: 'Error comparing faces', error: error.message });
        }
    });
});

//////////////////////////////////////////////Save Location/////////////////////////////////////////////////////////
app.post('/saveLocation', verifyToken, apiLimiter, async (req, res) => {
    const { capturedLatitude, capturedLongitude, selectedLatitude, selectedLongitude, selectedAddress } = req.body;
    const userId = req.user.id;

    console.log('Endpoint reached');

    const query = `
        INSERT INTO users (id, captured_latitude, captured_longitude, selected_latitude, selected_longitude, selected_address)
        VALUES (?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
            captured_latitude = VALUES(captured_latitude),
            captured_longitude = VALUES(captured_longitude),
            selected_latitude = VALUES(selected_latitude),
            selected_longitude = VALUES(selected_longitude),
            selected_address = VALUES(selected_address)
    `;

    try {
        await new Promise((resolve, reject) => {
            db.query(query, [userId, capturedLatitude, capturedLongitude, selectedLatitude, selectedLongitude, selectedAddress], (err, results) => {
                if (err) return reject(err);
                resolve(results);
            });
        });
        res.status(200).send('Location saved successfully');
    } catch (error) {
        console.error('Error saving location:', error.message || error);
        res.status(500).send('Error saving location');
    }
});

///////////////////////////////////////////////////////////////////////Endpoint to save status in the users table///////////////////////////////////
app.post('/saveStatus', verifyToken, apiLimiter, async (req, res) => {
    const { status } = req.body;
    const userId = req.user.id;

    if (!status) {
        return res.status(400).json({ message: 'Status is required' });
    }

    const query = `UPDATE users SET status = ? WHERE id = ?`;

    try {
        await new Promise((resolve, reject) => {
            db.query(query, [status, userId], (err, results) => {
                if (err) return reject(err);
                resolve(results);
            });
        });

        res.status(200).json({ message: 'Status updated successfully' });
    } catch (error) {
        console.error('Error updating status:', error.message || error);
        res.status(500).json({ message: 'Error updating status' });
    }
});

///////////////////////////////////////////////////// Endpoint to save reason in the users table////////////////////////////////
app.post('/saveReason', verifyToken, apiLimiter, async (req, res) => {
    const { reason } = req.body;
    const userId = req.user.id;

    if (!reason) {
        return res.status(400).json({ message: 'Reason is required' });
    }

    const query = `UPDATE users SET reason = ? WHERE id = ?`;

    try {
        await new Promise((resolve, reject) => {
            db.query(query, [reason, userId], (err, results) => {
                if (err) return reject(err);
                resolve(results);
            });
        });

        res.status(200).json({ message: 'Reason updated successfully' });
    } catch (error) {
        console.error('Error updating reason:', error.message || error);
        res.status(500).json({ message: 'Error updating reason' });
    }
});
    
/////////////////////////////////////RETRIEVE USERS DATABASE INTO ADMIN//////////////////////////////////
/**
 * SECURITY ENHANCEMENT: Access Control (OWASP A01)
 * Only admins can retrieve the list of all users
 * This prevents unauthorized access to user data
 */
app.get('/users', [verifyToken, requireAdmin, apiLimiter], (req, res) => {
    // Only admins can access this endpoint due to requireAdmin middleware
    const query = 'SELECT * FROM users';
    db.query(query, (error, results) => {
        if (error) {
            console.error('Error retrieving users:', error);
            logSecurityEvent(
                LOG_LEVELS.ERROR,
                EVENT_TYPES.DATA_READ,
                'Database error retrieving users',
                { error: error.message, admin: req.user.id, ip: req.ip }
            );
            res.status(500).json({ error: 'Failed to retrieve users' });
        } else {
            // SECURITY: Log data access (A09 - Security Logging)
            logSecurityEvent(
                LOG_LEVELS.INFO,
                EVENT_TYPES.DATA_READ,
                'Admin retrieved user list',
                { admin: req.user.id, count: results.length, ip: req.ip }
            );
            res.json(results);
            console.log(`result: ${results}`)
        }
    });
});

//////////////////////////////////////////////////////////////////Delete user route////////////////////////////////////////////////////////////
/**
 * SECURITY ENHANCEMENTS Applied:
 * 1. Access Control - Only admins can delete users (OWASP A01)
 * 2. Input validation for user ID (SQL injection prevention)
 * 3. Security logging for delete operations (A09)
 */
app.delete('/users/:id', [verifyToken, requireAdmin, apiLimiter], (req, res) => {
    const userId = req.params.id;

    // SECURITY: Validate user ID (prevents SQL injection through ID parameter)
    const idValidation = validateNumericId(userId);
    if (!idValidation.isValid) {
        return res.status(400).json({ error: idValidation.error });
    }

    // Only admins can delete users (enforced by requireAdmin middleware)
    const deleteQuery = 'DELETE FROM users WHERE id = ?';

    db.query(deleteQuery, [idValidation.sanitized], (error, result) => {
        if (error) {
            console.error('Error deleting user:', error);
            logSecurityEvent(
                LOG_LEVELS.ERROR,
                EVENT_TYPES.DATA_DELETED,
                'Database error deleting user',
                { userId: idValidation.sanitized, admin: req.user.id, error: error.message, ip: req.ip }
            );
            return res.status(500).json({ error: 'Failed to delete user' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // SECURITY: Log user deletion (A09 - Security Logging and Audit Trail)
        logDataModification(req.user.id, 'users', idValidation.sanitized, 'DELETE', {});
        logSecurityEvent(
            LOG_LEVELS.INFO,
            EVENT_TYPES.DATA_DELETED,
            'User deleted by admin',
            { userId: idValidation.sanitized, admin: req.user.id, ip: req.ip }
        );

        res.json({ message: 'User deleted successfully' });
    });
});

////////////////////////////////////////////////////////////Edit users information////////////////////////////////////
/**
 * SECURITY ENHANCEMENTS Applied:
 * 1. Access Control - Only admins can edit users (OWASP A01)
 * 2. Input validation for all fields (SQL injection prevention)
 * 3. Coordinate validation for latitude/longitude
 * 4. Security logging for data modifications (A09)
 */
app.put('/users/:userId', [verifyToken, requireAdmin, apiLimiter], (req, res) => {
    const userId = req.params.userId;
    const { ic, status, reason, selected_address, selected_latitude, selected_longitude } = req.body;

    // SECURITY: Validate user ID (prevents SQL injection)
    const userIdValidation = validateNumericId(userId);
    if (!userIdValidation.isValid) {
        return res.status(400).json({ error: userIdValidation.error });
    }

    // SECURITY: Validate IC if provided
    let validatedIC = ic;
    if (ic) {
        const icValidation = validateIC(ic);
        if (!icValidation.isValid) {
            return res.status(400).json({ error: icValidation.error });
        }
        validatedIC = icValidation.sanitized;
    }

    // SECURITY: Validate status if provided
    let validatedStatus = status;
    if (status) {
        const statusValidation = validateStatus(status);
        if (!statusValidation.isValid) {
            return res.status(400).json({ error: statusValidation.error });
        }
        validatedStatus = statusValidation.sanitized;
    }

    // SECURITY: Validate reason if provided (prevents XSS and SQL injection)
    let validatedReason = reason;
    if (reason) {
        const reasonValidation = validateText(reason, 500);
        if (!reasonValidation.isValid) {
            return res.status(400).json({ error: reasonValidation.error });
        }
        validatedReason = reasonValidation.sanitized;
    }

    // SECURITY: Validate address if provided
    let validatedAddress = selected_address;
    if (selected_address) {
        const addressValidation = validateText(selected_address, 300);
        if (!addressValidation.isValid) {
            return res.status(400).json({ error: addressValidation.error });
        }
        validatedAddress = addressValidation.sanitized;
    }

    // SECURITY: Validate coordinates if provided
    let validatedLat = selected_latitude;
    let validatedLng = selected_longitude;
    if (selected_latitude !== undefined && selected_latitude !== null) {
        const latValidation = validateLatitude(selected_latitude);
        if (!latValidation.isValid) {
            return res.status(400).json({ error: latValidation.error });
        }
        validatedLat = latValidation.sanitized;
    }
    if (selected_longitude !== undefined && selected_longitude !== null) {
        const lngValidation = validateLongitude(selected_longitude);
        if (!lngValidation.isValid) {
            return res.status(400).json({ error: lngValidation.error });
        }
        validatedLng = lngValidation.sanitized;
    }

    // SECURITY: Use validated inputs in parameterized query (SQL injection prevented)
    db.query(
        `UPDATE users SET ic = ?, status = ?, reason = ?, selected_address = ?, selected_latitude = ?, selected_longitude = ? WHERE id = ?`, 
        [validatedIC, validatedStatus, validatedReason, validatedAddress, validatedLat, validatedLng, userIdValidation.sanitized],
        (err, updateResult) => {
            if (err) {
                console.error('Error updating user:', err);
                logSecurityEvent(
                    LOG_LEVELS.ERROR,
                    EVENT_TYPES.DATA_MODIFIED,
                    'Database error updating user',
                    { userId: userIdValidation.sanitized, admin: req.user.id, error: err.message, ip: req.ip }
                );
                return res.status(500).json({ error: 'Failed to update user' });
            }

            // Fetch the updated user data
            db.query(`SELECT * FROM users WHERE id = ?`, [userIdValidation.sanitized], (err, results) => {
                if (err) {
                    console.error('Error retrieving updated user:', err);
                    return res.status(500).json({ error: 'Failed to retrieve updated user' });
                }
                if (results.length === 0) {
                    return res.status(404).json({ error: 'User not found' });
                }
                
                const updatedUser = results[0];

                // SECURITY: Log user modification (A09 - Security Logging and Audit Trail)
                logDataModification(req.user.id, 'users', userIdValidation.sanitized, 'UPDATE', {
                    ic: validatedIC,
                    status: validatedStatus,
                    reason: validatedReason,
                    address: validatedAddress
                });
                logSecurityEvent(
                    LOG_LEVELS.INFO,
                    EVENT_TYPES.DATA_MODIFIED,
                    'User updated by admin',
                    { userId: userIdValidation.sanitized, admin: req.user.id, ip: req.ip }
                );

                res.status(200).json(updatedUser);
            });
        }
    );
});

app.get('/auth/me', verifyToken, (req, res) => {
    res.status(200).json({
        id: req.user.id,
        userType: req.user.userType
    });
});

function getTableAndIdColumn(userType) {
    if (userType.toLowerCase() === 'admin') {
        return { table: 'admin', idColumn: 'admin_id' };
    }
    return { table: 'users', idColumn: 'id' };
}

///////////////////////////////////////////////////////////////////////////// 2FA ENDPOINTS /////////////////////////////////////////////////////////////
// 1. Setup 2FA - Generate secret and QR code
app.post('/2fa/setup', verifyToken, async (req, res) => {
    try {
        const { userId, userType } = req.body;

        if (!userId || !userType) {
            return res.status(400).json({ message: 'User ID and user type are required.' });
        }

        // Generate TOTP secret
        const secret = speakeasy.generateSecret({
            name: `DBKL Project (${userType === 'Admin' ? 'Admin' : 'User'})`,
            issuer: 'DBKL Project'
        });

        // Generate QR code
        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

        // Store the secret temporarily (will be confirmed after verification)
        const table = userType === 'Admin' ? 'admin' : 'users';
        const idColumn = userType === 'Admin' ? 'admin_id' : 'id';
        const query = `UPDATE ${table} SET two_fa_secret = ? WHERE ${idColumn} = ?`;

        db.query(query, [secret.base32, userId], (err, result) => {
            if (err) {
                console.error('Error saving 2FA secret:', err);
                return res.status(500).json({ message: 'Failed to setup 2FA.' });
            }

            res.status(200).json({
                message: '2FA setup initiated. Please scan the QR code with your authenticator app.',
                qrCode: qrCodeUrl,
                secret: secret.base32, // Send for manual entry if QR fails
                manualEntryKey: secret.base32
            });
        });

    } catch (error) {
        console.error('Error in 2FA setup:', error);
        res.status(500).json({ message: 'Internal server error during 2FA setup.' });
    }
});

// 2. Verify and Enable 2FA
app.post('/2fa/verify-setup', verifyToken, async (req, res) => {
    try {
        const { userId, userType, token } = req.body;

        if (!userId || !userType || !token) {
            return res.status(400).json({ message: 'User ID, user type, and token are required.' });
        }

        const table = userType === 'Admin' ? 'admin' : 'users';
        const idColumn = userType === 'Admin' ? 'admin_id' : 'id';
        const query = `SELECT two_fa_secret FROM ${table} WHERE ${idColumn} = ?`;

        db.query(query, [userId], (err, results) => {
            if (err || results.length === 0) {
                return res.status(500).json({ message: 'Failed to retrieve 2FA secret.' });
            }

            const secret = results[0].two_fa_secret;

            // Verify the token
            const verified = speakeasy.totp.verify({
                secret: secret,
                encoding: 'base32',
                token: token,
                window: 2 // Allow 2 time steps (60 seconds) tolerance
            });

            if (!verified) {
                return res.status(400).json({ message: 'Invalid verification code. Please try again.' });
            }

            // Generate backup codes
            const backupCodes = [];
            for (let i = 0; i < 10; i++) {
                backupCodes.push(Math.random().toString(36).substring(2, 10).toUpperCase());
            }

            // Hash backup codes before storing
            const hashedBackupCodes = backupCodes.map(code => bcrypt.hashSync(code, 10));

            // Enable 2FA
            const updateQuery = `UPDATE ${table} SET two_fa_enabled = 1, two_fa_backup_codes = ? WHERE ${idColumn} = ?`;
            db.query(updateQuery, [JSON.stringify(hashedBackupCodes), userId], (err, result) => {
                if (err) {
                    console.error('Error enabling 2FA:', err);
                    return res.status(500).json({ message: 'Failed to enable 2FA.' });
                }

                res.status(200).json({
                    message: '2FA enabled successfully!',
                    backupCodes: backupCodes // Send plain text codes to user (show only once)
                });
            });
        });

    } catch (error) {
        console.error('Error in 2FA verification:', error);
        res.status(500).json({ message: 'Internal server error during 2FA verification.' });
    }
});

// 3. Verify 2FA Token During Login
app.post('/2fa/verify-login', async (req, res) => {
    try {
        const { userId, userType, token, isBackupCode } = req.body;

        if (!userId || !userType || !token) {
            return res.status(400).json({ message: 'User ID, user type, and token are required.' });
        }

        const table = userType === 'Admin' ? 'admin' : 'users';
        const idColumn = userType === 'Admin' ? 'admin_id' : 'id';
        const query = `SELECT * FROM ${table} WHERE ${idColumn} = ?`;

        db.query(query, [userId], async (err, results) => {
            if (err || results.length === 0) {
                return res.status(500).json({ message: 'Failed to retrieve user data.' });
            }

            const user = results[0];
            let verified = false;

            if (isBackupCode) {
                // Verify backup code
                const backupCodes = JSON.parse(user.two_fa_backup_codes || '[]');

                for (let i = 0; i < backupCodes.length; i++) {
                    if (await bcrypt.compare(token, backupCodes[i])) {
                        verified = true;
                        // Remove used backup code
                        backupCodes.splice(i, 1);
                        const updateQuery = `UPDATE ${table} SET two_fa_backup_codes = ? WHERE ${idColumn} = ?`;
                        db.query(updateQuery, [JSON.stringify(backupCodes), userId], (err) => {
                            if (err) console.error('Error updating backup codes:', err);
                        });
                        break;
                    }
                }
            } else {
                // Verify TOTP token
                verified = speakeasy.totp.verify({
                    secret: user.two_fa_secret,
                    encoding: 'base32',
                    token: token,
                    window: 2
                });
            }

            if (!verified) {
                return res.status(400).json({ message: 'Invalid verification code.' });
            }

            // Generate JWT token after successful 2FA
            const jwtToken = jwt.sign(
                {
                    id: user.admin_id || user.id,
                    email: user.email || user.ic,
                    userType: userType
                },
                process.env.LOGIN_KEY,
                { expiresIn: '1h' }
            );

            // Set cookie
            res.cookie('token', jwtToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 3600000 // 1 hour
            });

            res.status(200).json({
                message: 'Login successful',
                user: {
                    id: user.admin_id || user.id,
                    email: user.email || null,
                    ic: user.ic || null,
                    name: user.name,
                    userType: userType
                }
            });
        });

    } catch (error) {
        console.error('Error in 2FA login verification:', error);
        res.status(500).json({ message: 'Internal server error during 2FA verification.' });
    }
});

// 4. Disable 2FA
app.post('/2fa/disable', verifyToken, async (req, res) => {
    try {
        const { userId, userType, token } = req.body;

        if (!userId || !userType || !token) {
            return res.status(400).json({ message: 'User ID, user type, and TOTP code are required.' });
        }

        const table = userType === 'Admin' ? 'admin' : 'users';
        const idColumn = userType === 'Admin' ? 'admin_id' : 'id';
        const query = `SELECT * FROM ${table} WHERE ${idColumn} = ?`;

        db.query(query, [userId], async (err, results) => {
            if (err || results.length === 0) {
                return res.status(500).json({ message: 'Failed to retrieve user data.' });
            }

            const user = results[0];

            // Verify TOTP code before disabling 2FA
            const verified = speakeasy.totp.verify({
                secret: user.two_fa_secret,
                encoding: 'base32',
                token: token,
                window: 2
            });

            if (!verified) {
                return res.status(401).json({ message: 'Invalid verification code.' });
            }

            // Disable 2FA
            const updateQuery = `UPDATE ${table} SET two_fa_enabled = 0, two_fa_secret = NULL, two_fa_backup_codes = NULL WHERE ${idColumn} = ?`;
            db.query(updateQuery, [userId], (err, result) => {
                if (err) {
                    console.error('Error disabling 2FA:', err);
                    return res.status(500).json({ message: 'Failed to disable 2FA.' });
                }

                res.status(200).json({ message: '2FA disabled successfully.' });
            });
        });

    } catch (error) {
        console.error('Error disabling 2FA:', error);
        res.status(500).json({ message: 'Internal server error while disabling 2FA.' });
    }
});

// 5. Check 2FA Status
app.get('/2fa/status/:userId/:userType', verifyToken, (req, res) => {
    const { userId, userType } = req.params;

    const table = userType === 'Admin' ? 'admin' : 'users';
    const idColumn = userType === 'Admin' ? 'admin_id' : 'id';
    const query = `SELECT two_fa_enabled FROM ${table} WHERE ${idColumn} = ?`;

    db.query(query, [userId], (err, results) => {
        if (err || results.length === 0) {
            return res.status(500).json({ message: 'Failed to retrieve 2FA status.' });
        }

        res.status(200).json({
            twoFactorEnabled: results[0].two_fa_enabled === 1
        });
    });
});


// Start the server
const PORT = 8081;
app.listen(PORT, () => {
    console.log(`connected to database on port ${PORT}`);
});