/**
 * SSRF Protection Module
 * 
 * Purpose: Prevents Server-Side Request Forgery (SSRF) attacks
 * by validating and sanitizing external URLs before making requests.
 * 
 * OWASP A10 - Server-Side Request Forgery (SSRF):
 * - Validates all external URLs before making requests
 * - Implements allowlist for trusted external services
 * - Prevents access to internal/private network ranges
 * - Adds timeout controls for external requests
 * 
 * Author: Security Implementation
 * Date: 2025-11-14
 */

import { URL } from 'url';

/**
 * List of allowed external API domains
 * Only requests to these domains are permitted
 * This is a whitelist approach for maximum security
 */
const ALLOWED_DOMAINS = [
    'api.imgbb.com',           // Image upload service
    'nominatim.openstreetmap.org', // Geocoding service (replacing Google Maps)
    'tile.openstreetmap.org',  // Map tiles
    'api.opencagedata.com',    // Alternative geocoding service
];

/**
 * List of blocked IP ranges (private networks and localhost)
 * Prevents SSRF attacks targeting internal infrastructure
 */
const BLOCKED_IP_RANGES = [
    /^127\./,           // Localhost
    /^10\./,            // Private network (10.0.0.0/8)
    /^172\.(1[6-9]|2\d|3[01])\./,  // Private network (172.16.0.0/12)
    /^192\.168\./,      // Private network (192.168.0.0/16)
    /^169\.254\./,      // Link-local
    /^::1$/,            // IPv6 localhost
    /^fe80:/,           // IPv6 link-local
    /^fc00:/,           // IPv6 unique local
    /^ff00:/,           // IPv6 multicast
];

/**
 * List of blocked hostnames
 */
const BLOCKED_HOSTNAMES = [
    'localhost',
    'metadata.google.internal',  // GCP metadata
    '169.254.169.254',           // AWS metadata
];

/**
 * Validates if a URL is safe to make requests to
 * Prevents SSRF attacks
 * 
 * @param {string} urlString - URL to validate
 * @returns {object} - {isValid: boolean, error: string}
 */
export const validateExternalUrl = (urlString) => {
    try {
        // Check if URL string is provided
        if (!urlString || typeof urlString !== 'string') {
            return { 
                isValid: false, 
                error: 'URL must be a non-empty string' 
            };
        }

        // Parse the URL
        const parsedUrl = new URL(urlString);

        // Only allow HTTP and HTTPS protocols
        if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
            console.warn(`[SSRF PROTECTION] Blocked non-HTTP protocol: ${parsedUrl.protocol}`);
            return { 
                isValid: false, 
                error: 'Only HTTP and HTTPS protocols are allowed' 
            };
        }

        // Check against blocked hostnames
        if (BLOCKED_HOSTNAMES.includes(parsedUrl.hostname.toLowerCase())) {
            console.warn(`[SSRF PROTECTION] Blocked hostname: ${parsedUrl.hostname}`);
            return { 
                isValid: false, 
                error: 'Access to this hostname is not allowed' 
            };
        }

        // Check if hostname matches blocked IP ranges
        for (const range of BLOCKED_IP_RANGES) {
            if (range.test(parsedUrl.hostname)) {
                console.warn(`[SSRF PROTECTION] Blocked private IP: ${parsedUrl.hostname}`);
                return { 
                    isValid: false, 
                    error: 'Access to private IP ranges is not allowed' 
                };
            }
        }

        // Check against allowed domains whitelist
        const isAllowed = ALLOWED_DOMAINS.some(domain => 
            parsedUrl.hostname === domain || 
            parsedUrl.hostname.endsWith('.' + domain)
        );

        if (!isAllowed) {
            console.warn(`[SSRF PROTECTION] Domain not in allowlist: ${parsedUrl.hostname}`);
            return { 
                isValid: false, 
                error: `Requests to ${parsedUrl.hostname} are not allowed. Only trusted external services are permitted.` 
            };
        }

        // Log successful validation
        console.log(`[SSRF PROTECTION] Validated URL: ${parsedUrl.hostname}`);
        
        return { 
            isValid: true, 
            error: null,
            sanitizedUrl: parsedUrl.toString()
        };

    } catch (error) {
        console.error(`[SSRF PROTECTION] Invalid URL format: ${error.message}`);
        return { 
            isValid: false, 
            error: 'Invalid URL format' 
        };
    }
};

/**
 * Safe wrapper for making external HTTP requests with SSRF protection
 * Use this instead of direct axios calls to external URLs
 * 
 * @param {string} url - URL to request
 * @param {object} options - Axios request options
 * @param {object} axios - Axios instance
 * @returns {Promise} - Axios response promise
 */
export const safeExternalRequest = async (url, options = {}, axios) => {
    // Validate URL
    const validation = validateExternalUrl(url);
    
    if (!validation.isValid) {
        const error = new Error(validation.error);
        error.name = 'SSRFProtectionError';
        throw error;
    }

    // Add timeout to prevent hanging requests (SSRF mitigation)
    const safeOptions = {
        ...options,
        timeout: options.timeout || 10000, // 10 second default timeout
        maxRedirects: options.maxRedirects || 5, // Limit redirects
    };

    // Log the request
    console.log(`[SSRF PROTECTION] Making safe external request to: ${validation.sanitizedUrl}`);

    try {
        // Make the request using the sanitized URL
        const response = await axios(validation.sanitizedUrl, safeOptions);
        
        // Log successful request
        console.log(`[SSRF PROTECTION] External request successful: ${validation.sanitizedUrl}`);
        
        return response;
    } catch (error) {
        console.error(`[SSRF PROTECTION] External request failed: ${error.message}`);
        throw error;
    }
};

/**
 * Validates image URL from external source
 * Additional validation for image URLs to prevent malicious content
 * 
 * @param {string} imageUrl - Image URL to validate
 * @returns {object} - {isValid: boolean, error: string}
 */
export const validateImageUrl = (imageUrl) => {
    // First validate as external URL
    const urlValidation = validateExternalUrl(imageUrl);
    
    if (!urlValidation.isValid) {
        return urlValidation;
    }

    try {
        const parsedUrl = new URL(imageUrl);
        const pathname = parsedUrl.pathname.toLowerCase();

        // Check for common image extensions
        const imageExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'];
        const hasImageExtension = imageExtensions.some(ext => pathname.endsWith(ext));

        // For API endpoints that return images, we might not have extensions
        // so we allow certain trusted domains without extension check
        const trustedImageDomains = ['api.imgbb.com', 'i.ibb.co'];
        const isTrustedDomain = trustedImageDomains.some(domain => 
            parsedUrl.hostname === domain || parsedUrl.hostname.endsWith('.' + domain)
        );

        if (!hasImageExtension && !isTrustedDomain) {
            console.warn(`[SSRF PROTECTION] URL does not appear to be an image: ${imageUrl}`);
            return { 
                isValid: false, 
                error: 'URL must point to a valid image file' 
            };
        }

        return { 
            isValid: true, 
            error: null,
            sanitizedUrl: urlValidation.sanitizedUrl
        };

    } catch (error) {
        return { 
            isValid: false, 
            error: 'Invalid image URL format' 
        };
    }
};

/**
 * Middleware to protect against SSRF in request body URLs
 * Validates any URL fields in the request body
 * 
 * @param {Array<string>} urlFields - Array of field names that contain URLs
 * @returns {Function} - Express middleware function
 * 
 * Usage: app.post('/endpoint', validateRequestUrls(['imageUrl', 'callbackUrl']), (req, res) => {...})
 */
export const validateRequestUrls = (urlFields = []) => {
    return (req, res, next) => {
        // Check each URL field in the request body
        for (const field of urlFields) {
            if (req.body[field]) {
                const validation = validateExternalUrl(req.body[field]);
                
                if (!validation.isValid) {
                    console.warn(`[SSRF PROTECTION] Invalid URL in field '${field}': ${req.body[field]}`);
                    return res.status(400).json({
                        message: `Invalid URL in field '${field}'`,
                        error: validation.error
                    });
                }

                // Replace with sanitized URL
                req.body[field] = validation.sanitizedUrl;
            }
        }

        next();
    };
};

/**
 * Add a domain to the allowed domains list
 * Use this to dynamically add trusted domains if needed
 * 
 * @param {string} domain - Domain to add to allowlist
 */
export const addAllowedDomain = (domain) => {
    if (!ALLOWED_DOMAINS.includes(domain)) {
        ALLOWED_DOMAINS.push(domain);
        console.log(`[SSRF PROTECTION] Added domain to allowlist: ${domain}`);
    }
};

/**
 * Get list of currently allowed domains
 * Useful for debugging and auditing
 * 
 * @returns {Array<string>} - Array of allowed domains
 */
export const getAllowedDomains = () => {
    return [...ALLOWED_DOMAINS];
};
