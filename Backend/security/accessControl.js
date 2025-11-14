/**
 * Access Control Module
 * 
 * Purpose: Implements Role-Based Access Control (RBAC) and authorization checks
 * to prevent broken access control vulnerabilities.
 * 
 * OWASP A01 - Broken Access Control:
 * - Implements proper authorization checks
 * - Role-based access control (RBAC)
 * - Resource ownership validation
 * - Prevents unauthorized access to data and functions
 * 
 * Author: Security Implementation
 * Date: 2025-11-14
 */

/**
 * Middleware to verify user is an Admin
 * Prevents regular users from accessing admin-only endpoints
 * 
 * Usage: app.get('/admin-endpoint', requireAdmin, (req, res) => {...})
 */
export const requireAdmin = (req, res, next) => {
    console.log('[REQUIRE ADMIN] Checking admin privileges...');
    console.log('[REQUIRE ADMIN] req.user:', req.user);
    
    // Check if user is authenticated
    if (!req.user) {
        console.warn(`[REQUIRE ADMIN] Unauthenticated access attempt to admin endpoint from IP: ${req.ip}`);
        return res.status(401).json({ 
            message: 'Authentication required',
            error: 'UNAUTHORIZED'
        });
    }

    console.log('[REQUIRE ADMIN] User type from token:', req.user.userType);
    console.log('[REQUIRE ADMIN] Checking if userType === "Admin":', req.user.userType === 'Admin');

    // Check if user type is Admin
    if (req.user.userType !== 'Admin') {
        console.warn(`[REQUIRE ADMIN] Non-admin user ${req.user.email} (userType: ${req.user.userType}) attempted to access admin endpoint from IP: ${req.ip}`);
        return res.status(403).json({ 
            message: 'Access denied. Admin privileges required.',
            error: 'FORBIDDEN',
            debug: { userType: req.user.userType, expected: 'Admin' }
        });
    }

    // Log successful admin access
    console.log(`[REQUIRE ADMIN] ✓ Admin ${req.user.email} authorized - accessing admin endpoint from IP: ${req.ip}`);
    next();
};

/**
 * Middleware to verify user is a regular user (not admin)
 * Prevents admins from accessing user-specific endpoints if needed
 * 
 * Usage: app.post('/user-endpoint', requireUser, (req, res) => {...})
 */
export const requireUser = (req, res, next) => {
    // Check if user is authenticated
    if (!req.user) {
        console.warn(`[ACCESS CONTROL] Unauthenticated access attempt to user endpoint from IP: ${req.ip}`);
        return res.status(401).json({ 
            message: 'Authentication required',
            error: 'UNAUTHORIZED'
        });
    }

    // Check if user type is users
    if (req.user.userType !== 'users') {
        console.warn(`[ACCESS CONTROL] Non-user account ${req.user.email} attempted to access user endpoint from IP: ${req.ip}`);
        return res.status(403).json({ 
            message: 'Access denied. User account required.',
            error: 'FORBIDDEN'
        });
    }

    // Log successful user access
    console.log(`[ACCESS CONTROL] User ${req.user.email} accessed user endpoint from IP: ${req.ip}`);
    next();
};

/**
 * Middleware to verify resource ownership
 * Ensures users can only access their own data
 * 
 * This function creates a middleware that checks if the user
 * is trying to access their own resource based on a parameter ID
 * 
 * @param {string} paramName - Name of the URL parameter containing the resource ID (default: 'id')
 * @returns {Function} Middleware function
 * 
 * Usage: app.get('/users/:id', verifyResourceOwnership('id'), (req, res) => {...})
 */
export const verifyResourceOwnership = (paramName = 'id') => {
    return (req, res, next) => {
        // Check if user is authenticated
        if (!req.user) {
            console.warn(`[ACCESS CONTROL] Unauthenticated resource access attempt from IP: ${req.ip}`);
            return res.status(401).json({ 
                message: 'Authentication required',
                error: 'UNAUTHORIZED'
            });
        }

        // Get the resource ID from URL parameters
        const resourceId = req.params[paramName];
        const userId = req.user.id;

        // Convert both to numbers for comparison
        const resourceIdNum = Number(resourceId);
        const userIdNum = Number(userId);

        // Admin bypass - admins can access any resource
        if (req.user.userType === 'Admin') {
            console.log(`[ACCESS CONTROL] Admin ${req.user.email} accessing resource ${resourceId}`);
            return next();
        }

        // Check if user is trying to access their own resource
        if (resourceIdNum !== userIdNum) {
            console.warn(`[ACCESS CONTROL] User ${userId} attempted to access resource ${resourceId} without authorization from IP: ${req.ip}`);
            return res.status(403).json({ 
                message: 'Access denied. You can only access your own resources.',
                error: 'FORBIDDEN'
            });
        }

        // Log successful ownership verification
        console.log(`[ACCESS CONTROL] User ${userId} accessing own resource ${resourceId}`);
        next();
    };
};

/**
 * Middleware to verify resource ownership from request body
 * Useful for POST/PUT requests where ID is in the body
 * 
 * @param {string} fieldName - Name of the field in request body containing the resource ID
 * @returns {Function} Middleware function
 * 
 * Usage: app.post('/update', verifyBodyResourceOwnership('userId'), (req, res) => {...})
 */
export const verifyBodyResourceOwnership = (fieldName = 'userId') => {
    return (req, res, next) => {
        // Check if user is authenticated
        if (!req.user) {
            console.warn(`[ACCESS CONTROL] Unauthenticated resource access attempt from IP: ${req.ip}`);
            return res.status(401).json({ 
                message: 'Authentication required',
                error: 'UNAUTHORIZED'
            });
        }

        // Get the resource ID from request body
        const resourceId = req.body[fieldName];
        const userId = req.user.id;

        // Admin bypass - admins can access any resource
        if (req.user.userType === 'Admin') {
            console.log(`[ACCESS CONTROL] Admin ${req.user.email} accessing resource via body field ${fieldName}`);
            return next();
        }

        // Convert both to numbers for comparison
        const resourceIdNum = Number(resourceId);
        const userIdNum = Number(userId);

        // Check if user is trying to access their own resource
        if (resourceIdNum !== userIdNum) {
            console.warn(`[ACCESS CONTROL] User ${userId} attempted to access resource ${resourceId} via body without authorization from IP: ${req.ip}`);
            return res.status(403).json({ 
                message: 'Access denied. You can only access your own resources.',
                error: 'FORBIDDEN'
            });
        }

        // Log successful ownership verification
        console.log(`[ACCESS CONTROL] User ${userId} accessing own resource ${resourceId} via body`);
        next();
    };
};

/**
 * Check if current user can modify a specific user record
 * Used within route handlers for fine-grained access control
 * 
 * @param {object} currentUser - The authenticated user (from req.user)
 * @param {number} targetUserId - ID of the user being modified
 * @returns {boolean} - True if access is allowed
 */
export const canModifyUser = (currentUser, targetUserId) => {
    // Admin can modify any user
    if (currentUser.userType === 'Admin') {
        return true;
    }

    // Users can only modify themselves
    return Number(currentUser.id) === Number(targetUserId);
};

/**
 * Check if current user can delete a specific user record
 * Only admins can delete users
 * 
 * @param {object} currentUser - The authenticated user (from req.user)
 * @returns {boolean} - True if access is allowed
 */
export const canDeleteUser = (currentUser) => {
    // Only admins can delete users
    return currentUser.userType === 'Admin';
};

/**
 * Check if current user can view a specific user's data
 * Admins can view all, users can view their own
 * 
 * @param {object} currentUser - The authenticated user (from req.user)
 * @param {number} targetUserId - ID of the user being viewed
 * @returns {boolean} - True if access is allowed
 */
export const canViewUser = (currentUser, targetUserId) => {
    // Admin can view any user
    if (currentUser.userType === 'Admin') {
        return true;
    }

    // Users can only view themselves
    return Number(currentUser.id) === Number(targetUserId);
};

/**
 * Middleware to log all access attempts for audit purposes
 * This supports OWASP A09 - Security Logging and Monitoring
 * 
 * Usage: app.use(logAccess);
 */
export const logAccess = (req, res, next) => {
    const logData = {
        timestamp: new Date().toISOString(),
        method: req.method,
        path: req.path,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        user: req.user ? {
            id: req.user.id,
            email: req.user.email || req.user.ic,
            userType: req.user.userType
        } : 'unauthenticated'
    };

    console.log('[ACCESS LOG]', JSON.stringify(logData));
    next();
};
