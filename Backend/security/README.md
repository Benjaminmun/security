# Security Modules Documentation

## Overview
This directory contains comprehensive security modules implementing OWASP Top 10 controls and SQL injection prevention.

## Modules

### 1. inputValidation.js
**Purpose:** Input validation and sanitization to prevent injection attacks.

**Usage:**
```javascript
import { validateEmail, validateIC, validateUsername } from './security/inputValidation.js';

// Validate email
const emailValidation = validateEmail(req.body.email);
if (!emailValidation.isValid) {
    return res.status(400).json({ message: emailValidation.error });
}

// Use sanitized value
const sanitizedEmail = emailValidation.sanitized;
```

**Available Functions:**
- `validateEmail(email)` - Email validation with SQL injection detection
- `validateIC(ic)` - Malaysian IC number validation
- `validateUsername(username)` - Username validation (alphanumeric + underscore)
- `validatePassword(password)` - Password strength validation
- `validateNumericId(id)` - Numeric ID validation
- `validateLatitude(lat)` - Latitude coordinate validation
- `validateLongitude(lng)` - Longitude coordinate validation
- `validateStatus(status)` - Status enum validation
- `validateText(text, maxLength)` - Text field sanitization
- `validateUserType(userType)` - User type validation (Admin/users)
- `validateBase64Image(base64Data)` - Base64 image validation

---

### 2. accessControl.js
**Purpose:** Role-Based Access Control (RBAC) - OWASP A01

**Usage:**
```javascript
import { requireAdmin, requireUser, verifyResourceOwnership } from './security/accessControl.js';

// Admin-only endpoint
app.get('/admin/users', requireAdmin, (req, res) => {
    // Only admins can access this
});

// User can only access their own data
app.get('/users/:id', verifyResourceOwnership('id'), (req, res) => {
    // req.user.id must match req.params.id (or be admin)
});
```

**Available Middleware:**
- `requireAdmin` - Ensures user is an admin
- `requireUser` - Ensures user is a regular user
- `verifyResourceOwnership(paramName)` - Ensures user owns the resource
- `verifyBodyResourceOwnership(fieldName)` - Ownership check for request body
- `logAccess` - Logs all access attempts

**Helper Functions:**
- `canModifyUser(currentUser, targetUserId)` - Check modify permission
- `canDeleteUser(currentUser)` - Check delete permission
- `canViewUser(currentUser, targetUserId)` - Check view permission

---

### 3. ssrfProtection.js
**Purpose:** Server-Side Request Forgery prevention - OWASP A10

**Usage:**
```javascript
import { validateExternalUrl, safeExternalRequest } from './security/ssrfProtection.js';
import axios from 'axios';

// Validate URL before making request
const validation = validateExternalUrl(externalUrl);
if (!validation.isValid) {
    return res.status(400).json({ message: validation.error });
}

// Make safe external request
try {
    const response = await safeExternalRequest(externalUrl, { method: 'POST' }, axios);
    // Process response
} catch (error) {
    // Handle SSRF protection error
}
```

**Available Functions:**
- `validateExternalUrl(urlString)` - Validates URL against allowlist
- `safeExternalRequest(url, options, axios)` - Safe wrapper for external requests
- `validateImageUrl(imageUrl)` - Image URL validation
- `validateRequestUrls(urlFields)` - Middleware for request body URL validation
- `addAllowedDomain(domain)` - Dynamically add trusted domain
- `getAllowedDomains()` - Get list of allowed domains

**Allowed Domains:**
- api.imgbb.com
- nominatim.openstreetmap.org
- tile.openstreetmap.org
- api.opencagedata.com

---

### 4. securityLogging.js
**Purpose:** Security event logging and monitoring - OWASP A09

**Usage:**
```javascript
import { 
    logSecurityEvent, 
    logFailedLogin, 
    logSuccessfulLogin,
    LOG_LEVELS,
    EVENT_TYPES 
} from './security/securityLogging.js';

// Log failed login
logFailedLogin(email, req.ip, req.headers['user-agent'], 'Invalid password');

// Log successful login
logSuccessfulLogin(email, req.ip, req.headers['user-agent'], 'Admin');

// Log custom security event
logSecurityEvent(
    LOG_LEVELS.WARN,
    EVENT_TYPES.ACCESS_DENIED,
    'Unauthorized access attempt',
    { userId: 123, resource: '/admin/users' }
);
```

**Available Functions:**
- `logSecurityEvent(level, eventType, message, metadata)` - Main logging function
- `logFailedLogin(identifier, ip, userAgent, reason)` - Log failed authentication
- `logSuccessfulLogin(identifier, ip, userAgent, userType)` - Log successful authentication
- `logAccessDenied(userId, resource, action, ip)` - Log authorization failures
- `logDataModification(userId, table, recordId, action, changes)` - Audit trail
- `logSqlInjectionAttempt(input, field, ip, endpoint)` - Log injection attempts
- `logSsrfAttempt(url, ip, endpoint)` - Log SSRF attempts
- `logRateLimitExceeded(ip, endpoint, attemptCount)` - Log rate limit hits
- `rotateLogIfNeeded(logFilePath, maxSizeMB)` - Rotate large log files
- `getRecentSecurityEvents(count)` - Retrieve recent events
- `initializeLogRotation()` - Start log rotation scheduler
- `logHttpRequest` - Middleware for HTTP request logging

**Log Levels:**
- `LOG_LEVELS.INFO` - Informational events
- `LOG_LEVELS.WARN` - Warning events
- `LOG_LEVELS.ERROR` - Error events
- `LOG_LEVELS.CRITICAL` - Critical security events (triggers alerts)

**Event Types:**
- Authentication: `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGOUT`, `ACCOUNT_LOCKED`
- Authorization: `ACCESS_GRANTED`, `ACCESS_DENIED`, `PRIVILEGE_ESCALATION_ATTEMPT`
- Data: `DATA_READ`, `DATA_MODIFIED`, `DATA_DELETED`
- Security: `SQL_INJECTION_ATTEMPT`, `XSS_ATTEMPT`, `SSRF_ATTEMPT`, `RATE_LIMIT_EXCEEDED`, `INVALID_INPUT`
- System: `CONFIG_CHANGE`, `DEPENDENCY_UPDATE`, `SECURITY_SCAN`

---

## Integration Example

Here's how to integrate all security modules into an endpoint:

```javascript
import express from 'express';
import { 
    validateEmail, 
    validatePassword 
} from './security/inputValidation.js';
import { requireAdmin } from './security/accessControl.js';
import { 
    logSecurityEvent,
    logFailedLogin,
    logSuccessfulLogin,
    LOG_LEVELS,
    EVENT_TYPES 
} from './security/securityLogging.js';

const app = express();

// Apply logging middleware globally
app.use(logHttpRequest);

// Login endpoint with comprehensive security
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Step 1: Validate email input
    const emailValidation = validateEmail(email);
    if (!emailValidation.isValid) {
        logSecurityEvent(
            LOG_LEVELS.WARN,
            EVENT_TYPES.INVALID_INPUT,
            'Invalid email format',
            { email, error: emailValidation.error, ip: req.ip }
        );
        return res.status(400).json({ message: emailValidation.error });
    }

    // Step 2: Validate password
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
        return res.status(400).json({ message: passwordValidation.error });
    }

    // Step 3: Use sanitized email in database query (parameterized)
    const query = "SELECT * FROM admin WHERE email = ?";
    db.query(query, [emailValidation.sanitized], async (err, results) => {
        if (err) {
            logSecurityEvent(
                LOG_LEVELS.ERROR,
                EVENT_TYPES.LOGIN_FAILURE,
                'Database error during login',
                { error: err.message, ip: req.ip }
            );
            return res.status(500).json({ message: 'Server error' });
        }

        if (results.length === 0) {
            logFailedLogin(emailValidation.sanitized, req.ip, req.headers['user-agent'], 'User not found');
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            logFailedLogin(emailValidation.sanitized, req.ip, req.headers['user-agent'], 'Invalid password');
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Success
        logSuccessfulLogin(emailValidation.sanitized, req.ip, req.headers['user-agent'], 'Admin');
        
        // Create JWT and respond
        const token = jwt.sign({ id: user.id, email: user.email }, process.env.LOGIN_KEY, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true });
        res.json({ message: 'Login successful' });
    });
});

// Admin-only endpoint with access control
app.get('/admin/users', requireAdmin, (req, res) => {
    // Only admins can access this
    const query = 'SELECT * FROM users';
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Server error' });
        }
        res.json(results);
    });
});

// User can only access their own data
app.get('/users/:id', verifyResourceOwnership('id'), (req, res) => {
    const userId = req.params.id;
    const query = 'SELECT * FROM users WHERE id = ?';
    db.query(query, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Server error' });
        }
        res.json(results[0]);
    });
});
```

---

## Log Files

All logs are stored in `Backend/logs/`:

- **security.log** - All security events
- **audit.log** - Audit trail of sensitive operations
- **error.log** - Error and critical events

Logs are automatically rotated when they exceed 10MB.

---

## Security Best Practices

1. **Always validate user input** before using it in queries
2. **Always use parameterized queries** - never string concatenation
3. **Apply appropriate access control** to all endpoints
4. **Log all security-relevant events** for audit trail
5. **Validate external URLs** before making requests
6. **Use sanitized values** from validation functions
7. **Check validation results** before proceeding
8. **Handle validation errors** appropriately

---

## Testing

To test SQL injection prevention:
```bash
cd Backend
node tests/sql-injection-tests.js
```

This will run comprehensive tests against all endpoints to verify SQL injection is prevented.

---

## Maintenance

### Log Rotation
Logs are automatically rotated when they exceed 10MB. To manually trigger rotation:

```javascript
import { rotateLogIfNeeded } from './security/securityLogging.js';
rotateLogIfNeeded('/path/to/logfile.log', 10); // 10MB max
```

### Adding Allowed Domains (SSRF)
To allow requests to a new trusted domain:

```javascript
import { addAllowedDomain } from './security/ssrfProtection.js';
addAllowedDomain('api.newservice.com');
```

### Viewing Recent Security Events
```javascript
import { getRecentSecurityEvents } from './security/securityLogging.js';

const events = getRecentSecurityEvents(100); // Last 100 events
console.log(events);
```

---

## Support

For questions or issues with security modules, contact the security team or review the SECURITY_IMPLEMENTATION_PROGRESS.md file for detailed implementation status.
