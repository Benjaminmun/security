/**
 * Protected Route Component
 * 
 * Purpose: Implements client-side access control for routes
 * Prevents unauthorized users from accessing restricted pages
 * 
 * SECURITY: OWASP A01 - Broken Access Control Prevention
 * - Verifies user authentication via JWT token
 * - Checks user role/type for admin-only routes
 * - Redirects unauthorized users to login page
 * 
 * Author: Security Implementation
 * Date: 2025-11-15
 */

import React, { useEffect, useState } from 'react';
import { Navigate } from 'react-router-dom';
import axios from 'axios';

/**
 * ProtectedRoute component that checks authentication and authorization
 * 
 * @param {React.Component} children - The component to render if authorized
 * @param {string} requiredRole - The role required to access this route ('Admin' or 'users')
 */
function ProtectedRoute({ children, requiredRole = null }) {
    const [isAuthorized, setIsAuthorized] = useState(null); // null = checking, true = authorized, false = not authorized
    const [loading, setLoading] = useState(true);
    const [redirectTo, setRedirectTo] = useState('/login');

    useEffect(() => {
        const verifyAuth = async () => {
            try {
                if (requiredRole === 'Admin') {
                    // For admin routes, verify by attempting to access admin endpoint
                    const response = await axios.get(
                        'http://localhost:8081/users',
                        { 
                            withCredentials: true,
                            validateStatus: (status) => status < 500 // Accept all non-server-error responses
                        }
                    );

                    if (response.status === 200) {
                        // User is authenticated and is admin
                        setIsAuthorized(true);
                    } else if (response.status === 403) {
                        // User is authenticated but not admin
                        console.warn('[SECURITY] Non-admin user attempted to access admin route');
                        setIsAuthorized(false);
                        setRedirectTo('/homepage'); // Redirect to user homepage
                    } else {
                        // Not authenticated
                        console.warn('[SECURITY] Unauthenticated access attempt to admin route');
                        setIsAuthorized(false);
                        setRedirectTo('/login');
                    }
                } else if (requiredRole === 'users') {
                    // For user routes, verify token by checking any authenticated endpoint
                    const response = await axios.post(
                        'http://localhost:8081/auth/extend',
                        {},
                        { 
                            withCredentials: true,
                            validateStatus: (status) => status < 500
                        }
                    );

                    if (response.status === 200) {
                        // User is authenticated
                        setIsAuthorized(true);
                    } else {
                        // Not authenticated
                        console.warn('[SECURITY] Unauthenticated access attempt to user route');
                        setIsAuthorized(false);
                        setRedirectTo('/login');
                    }
                } else {
                    // No specific role required, just check authentication
                    const response = await axios.post(
                        'http://localhost:8081/auth/extend',
                        {},
                        { 
                            withCredentials: true,
                            validateStatus: (status) => status < 500
                        }
                    );

                    if (response.status === 200) {
                        setIsAuthorized(true);
                    } else {
                        setIsAuthorized(false);
                        setRedirectTo('/login');
                    }
                }
            } catch (error) {
                console.error('[SECURITY] Auth verification error:', error);
                setIsAuthorized(false);
                setRedirectTo('/login');
            } finally {
                setLoading(false);
            }
        };

        verifyAuth();
    }, [requiredRole]);

    // Show loading state while checking authentication
    if (loading) {
        return (
            <div style={{
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                height: '100vh',
                fontSize: '18px',
                color: '#666'
            }}>
                🔒 Verifying access...
            </div>
        );
    }

    // Not authorized - show alert and redirect
    if (!isAuthorized) {
        if (redirectTo === '/homepage') {
            // User is authenticated but doesn't have admin privileges
            alert(`🛡️ SECURITY: Access Denied\n\nYou do not have permission to access this page.\nAdmin privileges required.\n\nRedirecting to user homepage...`);
        }
        return <Navigate to={redirectTo} replace />;
    }

    // Authorized - render children
    return children;
}

export default ProtectedRoute;
