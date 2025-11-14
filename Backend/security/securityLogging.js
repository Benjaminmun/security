/**
 * Security Logging and Monitoring Module
 * 
 * Purpose: Implements comprehensive security event logging and monitoring
 * to detect and respond to security incidents.
 * 
 * OWASP A09 - Security Logging and Monitoring Failures:
 * - Logs all security-relevant events
 * - Tracks failed authentication attempts
 * - Creates audit trails for sensitive operations
 * - Implements log rotation and retention
 * - Provides monitoring and alerting capabilities
 * 
 * Author: Security Implementation
 * Date: 2025-11-14
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Get current directory for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Log file paths
const LOG_DIR = path.join(__dirname, '..', 'logs');
const SECURITY_LOG_FILE = path.join(LOG_DIR, 'security.log');
const AUDIT_LOG_FILE = path.join(LOG_DIR, 'audit.log');
const ERROR_LOG_FILE = path.join(LOG_DIR, 'error.log');

// Ensure log directory exists
if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
}

/**
 * Log levels for categorizing security events
 */
export const LOG_LEVELS = {
    INFO: 'INFO',
    WARN: 'WARN',
    ERROR: 'ERROR',
    CRITICAL: 'CRITICAL'
};

/**
 * Security event types for classification
 */
export const EVENT_TYPES = {
    // Authentication events
    LOGIN_SUCCESS: 'LOGIN_SUCCESS',
    LOGIN_FAILURE: 'LOGIN_FAILURE',
    LOGOUT: 'LOGOUT',
    ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
    
    // Authorization events
    ACCESS_GRANTED: 'ACCESS_GRANTED',
    ACCESS_DENIED: 'ACCESS_DENIED',
    PRIVILEGE_ESCALATION_ATTEMPT: 'PRIVILEGE_ESCALATION_ATTEMPT',
    
    // Data access events
    DATA_READ: 'DATA_READ',
    DATA_MODIFIED: 'DATA_MODIFIED',
    DATA_DELETED: 'DATA_DELETED',
    
    // Security events
    SQL_INJECTION_ATTEMPT: 'SQL_INJECTION_ATTEMPT',
    XSS_ATTEMPT: 'XSS_ATTEMPT',
    SSRF_ATTEMPT: 'SSRF_ATTEMPT',
    RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
    INVALID_INPUT: 'INVALID_INPUT',
    
    // System events
    CONFIG_CHANGE: 'CONFIG_CHANGE',
    DEPENDENCY_UPDATE: 'DEPENDENCY_UPDATE',
    SECURITY_SCAN: 'SECURITY_SCAN'
};

/**
 * Format log entry with timestamp and metadata
 * 
 * @param {string} level - Log level (INFO, WARN, ERROR, CRITICAL)
 * @param {string} eventType - Type of event
 * @param {string} message - Log message
 * @param {object} metadata - Additional context data
 * @returns {string} - Formatted log entry
 */
const formatLogEntry = (level, eventType, message, metadata = {}) => {
    const timestamp = new Date().toISOString();
    const entry = {
        timestamp,
        level,
        eventType,
        message,
        ...metadata
    };
    
    return JSON.stringify(entry) + '\n';
};

/**
 * Write log entry to file
 * 
 * @param {string} filePath - Path to log file
 * @param {string} entry - Formatted log entry
 */
const writeToLog = (filePath, entry) => {
    try {
        fs.appendFileSync(filePath, entry, 'utf8');
    } catch (error) {
        console.error(`Failed to write to log file ${filePath}:`, error.message);
    }
};

/**
 * Main security logging function
 * Logs security events to appropriate log files
 * 
 * @param {string} level - Log level
 * @param {string} eventType - Event type
 * @param {string} message - Log message
 * @param {object} metadata - Additional context
 */
export const logSecurityEvent = (level, eventType, message, metadata = {}) => {
    const entry = formatLogEntry(level, eventType, message, metadata);
    
    // Write to security log
    writeToLog(SECURITY_LOG_FILE, entry);
    
    // Also log to console for real-time monitoring
    const consoleMessage = `[${level}] [${eventType}] ${message}`;
    
    switch (level) {
        case LOG_LEVELS.INFO:
            console.log(consoleMessage, metadata);
            break;
        case LOG_LEVELS.WARN:
            console.warn(consoleMessage, metadata);
            break;
        case LOG_LEVELS.ERROR:
        case LOG_LEVELS.CRITICAL:
            console.error(consoleMessage, metadata);
            // Write critical errors to separate error log
            writeToLog(ERROR_LOG_FILE, entry);
            break;
    }
    
    // Alert on critical events (in production, this could trigger email/SMS)
    if (level === LOG_LEVELS.CRITICAL) {
        alertCriticalEvent(eventType, message, metadata);
    }
};

/**
 * Log failed login attempts
 * Helps detect brute force attacks
 * 
 * @param {string} identifier - Username, email, or IC
 * @param {string} ip - IP address of attacker
 * @param {string} userAgent - User agent string
 * @param {string} reason - Reason for failure
 */
export const logFailedLogin = (identifier, ip, userAgent, reason = 'Invalid credentials') => {
    logSecurityEvent(
        LOG_LEVELS.WARN,
        EVENT_TYPES.LOGIN_FAILURE,
        `Failed login attempt for ${identifier}`,
        {
            identifier,
            ip,
            userAgent,
            reason
        }
    );
};

/**
 * Log successful login
 * Creates audit trail of authentication
 * 
 * @param {string} identifier - Username, email, or IC
 * @param {string} ip - IP address
 * @param {string} userAgent - User agent string
 * @param {string} userType - Admin or users
 */
export const logSuccessfulLogin = (identifier, ip, userAgent, userType) => {
    logSecurityEvent(
        LOG_LEVELS.INFO,
        EVENT_TYPES.LOGIN_SUCCESS,
        `Successful login for ${identifier}`,
        {
            identifier,
            ip,
            userAgent,
            userType
        }
    );
    
    // Also write to audit log
    const auditEntry = formatLogEntry(
        LOG_LEVELS.INFO,
        EVENT_TYPES.LOGIN_SUCCESS,
        `User ${identifier} logged in`,
        { identifier, ip, userType }
    );
    writeToLog(AUDIT_LOG_FILE, auditEntry);
};

/**
 * Log access denied events
 * Helps detect unauthorized access attempts
 * 
 * @param {string} userId - User ID attempting access
 * @param {string} resource - Resource being accessed
 * @param {string} action - Action attempted
 * @param {string} ip - IP address
 */
export const logAccessDenied = (userId, resource, action, ip) => {
    logSecurityEvent(
        LOG_LEVELS.WARN,
        EVENT_TYPES.ACCESS_DENIED,
        `Access denied for user ${userId}`,
        {
            userId,
            resource,
            action,
            ip
        }
    );
};

/**
 * Log data modification events
 * Creates audit trail of data changes
 * 
 * @param {string} userId - User making the change
 * @param {string} table - Database table
 * @param {string} recordId - Record being modified
 * @param {string} action - Type of modification (UPDATE, DELETE)
 * @param {object} changes - What was changed
 */
export const logDataModification = (userId, table, recordId, action, changes = {}) => {
    const auditEntry = formatLogEntry(
        LOG_LEVELS.INFO,
        EVENT_TYPES.DATA_MODIFIED,
        `${action} on ${table}`,
        {
            userId,
            table,
            recordId,
            action,
            changes
        }
    );
    
    writeToLog(AUDIT_LOG_FILE, auditEntry);
};

/**
 * Log SQL injection attempt
 * Critical security event requiring immediate attention
 * 
 * @param {string} input - Malicious input detected
 * @param {string} field - Field where injection was attempted
 * @param {string} ip - IP address of attacker
 * @param {string} endpoint - API endpoint targeted
 */
export const logSqlInjectionAttempt = (input, field, ip, endpoint) => {
    logSecurityEvent(
        LOG_LEVELS.CRITICAL,
        EVENT_TYPES.SQL_INJECTION_ATTEMPT,
        `SQL injection attempt detected`,
        {
            input: input.substring(0, 100), // Truncate for log safety
            field,
            ip,
            endpoint
        }
    );
};

/**
 * Log SSRF attempt
 * Critical security event
 * 
 * @param {string} url - Malicious URL detected
 * @param {string} ip - IP address of attacker
 * @param {string} endpoint - API endpoint targeted
 */
export const logSsrfAttempt = (url, ip, endpoint) => {
    logSecurityEvent(
        LOG_LEVELS.CRITICAL,
        EVENT_TYPES.SSRF_ATTEMPT,
        `SSRF attempt detected`,
        {
            url,
            ip,
            endpoint
        }
    );
};

/**
 * Log rate limit exceeded
 * May indicate DoS attack or scraping attempt
 * 
 * @param {string} ip - IP address
 * @param {string} endpoint - API endpoint
 * @param {number} attemptCount - Number of attempts
 */
export const logRateLimitExceeded = (ip, endpoint, attemptCount) => {
    logSecurityEvent(
        LOG_LEVELS.WARN,
        EVENT_TYPES.RATE_LIMIT_EXCEEDED,
        `Rate limit exceeded`,
        {
            ip,
            endpoint,
            attemptCount
        }
    );
};

/**
 * Alert on critical security events
 * In production, this should trigger real-time notifications
 * 
 * @param {string} eventType - Type of critical event
 * @param {string} message - Event message
 * @param {object} metadata - Event metadata
 */
const alertCriticalEvent = (eventType, message, metadata) => {
    // For now, just log to console
    // In production, integrate with:
    // - Email notifications
    // - SMS alerts
    // - SIEM systems
    // - Slack/Teams notifications
    // - PagerDuty or similar
    
    console.error('\n=== CRITICAL SECURITY ALERT ===');
    console.error(`Event Type: ${eventType}`);
    console.error(`Message: ${message}`);
    console.error(`Details:`, metadata);
    console.error('===============================\n');
    
    // TODO: Implement actual alerting mechanism
    // Example: sendEmailAlert(eventType, message, metadata);
    // Example: sendSlackNotification(eventType, message, metadata);
};

/**
 * Rotate logs when they exceed size limit
 * Prevents log files from growing indefinitely
 * 
 * @param {string} logFilePath - Path to log file
 * @param {number} maxSizeMB - Maximum file size in MB
 */
export const rotateLogIfNeeded = (logFilePath, maxSizeMB = 10) => {
    try {
        if (!fs.existsSync(logFilePath)) {
            return;
        }

        const stats = fs.statSync(logFilePath);
        const fileSizeMB = stats.size / (1024 * 1024);

        if (fileSizeMB >= maxSizeMB) {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const rotatedPath = `${logFilePath}.${timestamp}`;
            
            fs.renameSync(logFilePath, rotatedPath);
            console.log(`[LOG ROTATION] Rotated ${logFilePath} to ${rotatedPath}`);
        }
    } catch (error) {
        console.error(`Error rotating log file ${logFilePath}:`, error.message);
    }
};

/**
 * Get recent security events from log file
 * Useful for security dashboard
 * 
 * @param {number} count - Number of recent events to retrieve
 * @returns {Array} - Array of log entries
 */
export const getRecentSecurityEvents = (count = 100) => {
    try {
        if (!fs.existsSync(SECURITY_LOG_FILE)) {
            return [];
        }

        const content = fs.readFileSync(SECURITY_LOG_FILE, 'utf8');
        const lines = content.trim().split('\n');
        const recentLines = lines.slice(-count);

        return recentLines.map(line => {
            try {
                return JSON.parse(line);
            } catch {
                return null;
            }
        }).filter(entry => entry !== null);
    } catch (error) {
        console.error('Error reading security log:', error.message);
        return [];
    }
};

/**
 * Initialize log rotation scheduler
 * Runs log rotation check periodically
 */
export const initializeLogRotation = () => {
    // Check log rotation every hour
    setInterval(() => {
        rotateLogIfNeeded(SECURITY_LOG_FILE);
        rotateLogIfNeeded(AUDIT_LOG_FILE);
        rotateLogIfNeeded(ERROR_LOG_FILE);
    }, 60 * 60 * 1000); // 1 hour

    console.log('[SECURITY LOGGING] Log rotation scheduler initialized');
};

/**
 * Express middleware to log all HTTP requests
 * Creates comprehensive audit trail
 * 
 * Usage: app.use(logHttpRequest);
 */
export const logHttpRequest = (req, res, next) => {
    const startTime = Date.now();

    // Log response when finished
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        const metadata = {
            method: req.method,
            path: req.path,
            statusCode: res.statusCode,
            duration: `${duration}ms`,
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            user: req.user ? {
                id: req.user.id,
                type: req.user.userType
            } : 'anonymous'
        };

        // Determine log level based on status code
        let level = LOG_LEVELS.INFO;
        if (res.statusCode >= 400 && res.statusCode < 500) {
            level = LOG_LEVELS.WARN;
        } else if (res.statusCode >= 500) {
            level = LOG_LEVELS.ERROR;
        }

        logSecurityEvent(
            level,
            'HTTP_REQUEST',
            `${req.method} ${req.path} - ${res.statusCode}`,
            metadata
        );
    });

    next();
};
