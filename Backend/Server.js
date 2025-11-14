import express from 'express';
import mysql from 'mysql';
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

//login 
import jwt from 'jsonwebtoken'; // import json web token

const app = express();

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

// Enhanced Login rate limiter - prevents brute force attacks with precise timing
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login attempts per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.ip + (req.headers['user-agent'] || '');
  },
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

// Account-specific rate limiter with precise timing
const accountLoginLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Max attempts per account per hour
  keyGenerator: (req) => {
    const identifier = req.body.email || req.body.ic || 'unknown';
    return identifier + req.ip;
  },
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

    res.setHeader('Retry-After', waitTimeInSeconds);
    
    res.status(429).json({
      error: "Too many accounts created from this IP",
      message: `Too many registration attempts. Please try again in ${waitTimeInMinutes} minute(s).`,
      retryAfter: waitTimeInSeconds
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

// Request logging middleware
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - IP: ${req.ip}`);
    next();
});

// Middleware
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));

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

  console.log('Token from cookies:', token);

  if (!token) {
    return res.status(403).json({ message: 'No token provided.' });
  }

  jwt.verify(token, process.env.LOGIN_KEY, (err, decoded) => {
    if (err) {
      console.error('Invalid token:', err);
      return res.status(401).json({ message: 'Invalid token.' });
    }
    req.user = decoded;
    next();
  });
};

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
app.post('/Login', [loginLimiter, accountLoginLimiter], async (req, res) => {
    const { email, password, ic, userType } = req.body;
    const clientIP = req.ip;
    const userAgent = req.headers['user-agent'];

    console.log(`Login attempt from IP: ${clientIP}, User-Type: ${userType}`);

    // Enhanced input validation
    if (userType === "Admin") {
        if (!email || !password) {
            console.warn(`Missing credentials - Admin login attempt from IP: ${clientIP}`);
            return res.status(400).json({ message: 'Email and password are required for Admin login.' });
        }
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: 'Invalid email format.' });
        }
    } else if (userType === "users") {
        if (!ic || !password) {
            console.warn(`Missing credentials - User login attempt from IP: ${clientIP}`);
            return res.status(400).json({ message: 'IC and password are required for User login.' });
        }
        if (ic.length < 8) {
            return res.status(400).json({ message: 'Invalid IC format.' });
        }
    } else {
        console.warn(`Invalid user type: ${userType} from IP: ${clientIP}`);
        return res.status(400).json({ message: 'Invalid user type.' });
    }

    // Password length check
    if (password.length < 1) {
        return res.status(400).json({ message: 'Password is required.' });
    }

    try {
        let query;
        let parameter;
        let identifier;

        // Check for account lock
        identifier = userType === "Admin" ? email : ic;
        const accountLock = isAccountLocked(identifier);
        if (accountLock) {
            const remainingTime = Math.ceil((accountLock.until - Date.now()) / 1000 / 60);
            console.warn(`Login attempt to locked account: ${identifier} from IP: ${clientIP}`);
            return res.status(423).json({ 
                message: `Account is temporarily locked due to too many failed attempts. Please try again in ${remainingTime} minute(s).`,
                retryAfter: Math.ceil((accountLock.until - Date.now()) / 1000)
            });
        }

        // Determine query and parameter based on userType
        if (userType === "Admin") {
            query = "SELECT * FROM admin WHERE email = ?";
            parameter = [email];
        } else {
            query = "SELECT * FROM users WHERE ic = ?";
            parameter = [ic];
        }

        // Execute database query
        db.query(query, parameter, async (err, results) => {
            if (err) {
                console.error(`Database error during login for ${identifier}:`, err);
                return res.status(500).json({ message: 'Server error' });
            }

            if (results.length === 0) {
                console.warn(`Failed login attempt - User not found: ${identifier} from IP: ${clientIP}`);
                logFailedAttempt(identifier, clientIP, userAgent);
                
                // Check if we should lock the account (after multiple failed attempts)
                const failedAttemptsQuery = "SELECT COUNT(*) as count FROM login_attempts WHERE identifier = ? AND success = false AND attempt_time > DATE_SUB(NOW(), INTERVAL 30 MINUTE)";
                db.query(failedAttemptsQuery, [identifier], (err, attemptResults) => {
                    if (!err && attemptResults[0].count >= 5) {
                        const lock = lockAccount(identifier);
                        console.warn(`Account locked due to multiple failed attempts: ${identifier}`);
                    }
                });

                return res.status(401).json({ message: 'Invalid credentials' });
            }

            const user = results[0];

            // Compare password with the hashed password in the database
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                console.warn(`Failed login attempt - Invalid password for: ${identifier} from IP: ${clientIP}`);
                logFailedAttempt(identifier, clientIP, userAgent);

                // Check if we should lock the account
                const failedAttemptsQuery = "SELECT COUNT(*) as count FROM login_attempts WHERE identifier = ? AND success = false AND attempt_time > DATE_SUB(NOW(), INTERVAL 30 MINUTE)";
                db.query(failedAttemptsQuery, [identifier], (err, attemptResults) => {
                    if (!err && attemptResults[0].count >= 5) {
                        const lock = lockAccount(identifier);
                        console.warn(`Account locked due to multiple failed attempts: ${identifier}`);
                    }
                });

                return res.status(401).json({ message: 'Invalid credentials' });
            }

            // Check if account is locked in database
            if (user.is_locked) {
                console.warn(`Login attempt to locked account: ${identifier} from IP: ${clientIP}`);
                return res.status(423).json({ message: 'Account is locked. Please contact administrator.' });
            }

            // Create a JSON Web Token (JWT) for authenticated users
            const token = jwt.sign(
                { 
                    id: user.id, 
                    email: user.email || user.ic, 
                    userType: userType,
                    loginTime: Date.now()
                },
                process.env.LOGIN_KEY,
                { expiresIn: '1h' }
            );

            // Set the JWT as an HttpOnly cookie
            res.cookie('token', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 3600000
            });

            // Log successful login
            console.log(`Successful login: ${identifier} from IP: ${clientIP}`);

            // Clear any failed attempts on successful login
            clearFailedAttempts(identifier);
            accountLocks.delete(identifier); // Remove lock on successful login

            // Log successful attempt
            const successQuery = "INSERT INTO login_attempts (identifier, ip_address, user_agent, success, attempt_time) VALUES (?, ?, ?, ?, NOW())";
            db.query(successQuery, [identifier, clientIP, userAgent, true], (err) => {
                if (err) console.error('Error logging successful attempt:', err);
            });

            // Respond with user info (without password) and success message
            return res.json({
                message: 'Login successful',
                user: {
                    id: user.id,
                    email: user.email || user.ic,
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
app.post('/check-account-exist', apiLimiter, (req, res) => {
    const { username, email, ic, userType } = req.body;

    if(userType === "Admin"){

    const emailQuery = "SELECT * FROM admin WHERE email = ?";
    db.query(emailQuery, [email], (err, emailResults) => {
        if (err) return res.status(500).json({ message: 'Error checking account existence.' });

        if (emailResults.length > 0) {
            return res.json({ message: 'An account already exists with this email.' });
        }

        const usernameQuery = "SELECT * FROM admin WHERE username = ?";
        db.query(usernameQuery, [username], (err, usernameResults) => {
            if (err) return res.status(500).json({ message: 'Error checking account existence.' });

            if (usernameResults.length > 0) {
                return res.status(409).json({ message: 'An account already exists with this email.' });
            }

            return res.json({ message: 'No existing account with this email or username.' });
        });
    });
    }else if(userType === "users"){
        const icQuery = "SELECT * FROM users WHERE ic = ?";

        db.query(icQuery,[ic], (err, icResults) =>{
            if (err) return res.status(500).json({ message: 'Error checking account existence.' });
            
            
            if (icResults.length > 0) {
                return res.status(409).json({ message: 'An account already exists with this IC.' });
            }

            return res.json({message: "No existing account with this IC."})
        
        });
    }else{
        return res.status(400).json({ message: 'Invalid user type.' });
    }
});

/////////////////////////////////////////////////////////////////////////////// Register endpoint///////////////////////////////////////////////////
app.post('/register', registerLimiter, async (req, res) => {
    console.log('Received request:', req.body);
    const { username, email, password, ic, userType} = req.body;

    if(userType === "Admin"){
        if (!username || !email || !password || !isStrongPassword(password)) {
            return res.status(400).json({ message: 'All fields are required and password must be at least 8 characters with uppercase, lowercase, number, and symbol.' });
        }
    }else{
        if(!ic || !password || !isStrongPassword(password)) {
            return res.status(400).json({ message: 'All fields are required and password must be at least 8 characters with uppercase, lowercase, number, and symbol.' });
        }
    }
    
    try {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        let parameter;
        let query; 

        if(userType === "Admin"){
            query = "INSERT INTO admin (email, username, password) VALUES (?, ?, ?)";
            parameter = [email, username, hashedPassword]
        } else if(userType === "users"){
            query = "INSERT INTO users (IC, password) VALUES (?, ?)";
            parameter = [ic, hashedPassword]
        }else{
            return res.status(400).json({ message: 'Invalid user type.' });
        }
           
        db.query(query, parameter, (err, data) => {

            if (err) {
                console.error('Error inserting data:', err.code, err.message);
                return res.status(500).json({ message: 'Error !!', error: err.message });
            }

            if (data.affectedRows > 0) {
                console.log('signup successful', req.body)
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

const uploadToImgBB = async (imageBase64) => {
    try {
        const form = new FormData();
        form.append('key', process.env.IMGBB_API_KEY);
        form.append('image', imageBase64);

        const response = await axios.post('https://api.imgbb.com/1/upload', form, {
            headers: form.getHeaders(),
            maxBodyLength: Infinity,
        });

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
    
/////////////////////////////////////RETRIVE USERS DATABASE INTO ADMIN//////////////////////////////////
app.get('/users', apiLimiter, (req, res) => {
    const query = 'SELECT * FROM users';
    db.query(query, (error, results) => {
        if (error) {
            console.error('Error retrieving users:', error);
            res.status(500).json({ error: 'Failed to retrieve users' });
        } else {
            res.json(results);
            console.log(`result: ${results}`)
        }
    });
});

//////////////////////////////////////////////////////////////////Delete user route////////////////////////////////////////////////////////////
app.delete('/users/:id', apiLimiter, (req, res) => {
    const userId = req.params.id;
    const deleteQuery = 'DELETE FROM users WHERE id = ?';

    db.query(deleteQuery, [userId], (error, result) => {
        if (error) {
            console.error('Error deleting user:', error);
            return res.status(500).json({ error: 'Failed to delete user' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ message: 'User deleted successfully' });
    });
});

////////////////////////////////////////////////////////////Edit users information////////////////////////////////////
app.put('/users/:userId', apiLimiter, (req, res) => {
    const userId = req.params.userId;
    const { ic, status, reason, selected_address, selected_latitude, selected_longitude } = req.body;

    db.query(
        `UPDATE users SET ic = ?, status = ?, reason = ?, selected_address = ?, selected_latitude = ?, selected_longitude = ? WHERE id = ?`, 
        [ic, status, reason, selected_address, selected_latitude, selected_longitude, userId],
        (err, updateResult) => {
            if (err) {
                console.error('Error updating user:', err);
                return res.status(500).json({ error: 'Failed to update user' });
            }

            db.query(`SELECT * FROM users WHERE id = ?`, [userId], (err, results) => {
                if (err) {
                    console.error('Error retrieving updated user:', err);
                    return res.status(500).json({ error: 'Failed to retrieve updated user' });
                }
                if (results.length === 0) {
                    return res.status(404).json({ error: 'User not found' });
                }
                const updatedUser = results[0];
                res.status(200).json(updatedUser);
            });
        }
    );
});

// Start the server
const PORT = 8081;
app.listen(PORT, () => {
    console.log(`connected to database on port ${PORT}`);
});