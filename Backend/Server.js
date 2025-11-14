import express from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors';
import bcrypt from 'bcrypt'; // hash password
import multer from 'multer'; // handle multiple form content
import cookieParser from 'cookie-parser'; // httpOnly cookie
import axios from 'axios';
import querystring from 'querystring';
import bodyParser from 'body-parser';
import FormData from 'form-data';

// .env
import dotenv from 'dotenv';
dotenv.config();

// login 
import jwt from 'jsonwebtoken'; // import json web token

// Rate limiting
import rateLimit from 'express-rate-limit';

const app = express();

// Use cookie-parser middleware
app.use(cookieParser());

// Load environment variables
dotenv.config();

// Middleware
app.use(bodyParser.json({ limit: '10mb' })); // Increase the limit to 10mb
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true })); // Increase the limit for URL-encoded data
app.use(cors({
    origin: 'http://localhost:3000',  // Change to the client URL if different
    credentials: true                 // Allow cookies to be sent
}));

//////////////////////////////////////////////////////////////////////////////// MySQL connection////////////////////////////////////////////////////
const db = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "",
    database: "dbkl_project",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

///////////////////////////////////////////////////////////////////////// Rate Limiting Configuration //////////////////////////////////////////////////

// Login rate limiter - prevents brute force attacks
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login requests per windowMs
  message: {
    error: "Too many login attempts from this IP, please try again after 15 minutes."
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Registration rate limiter - prevents mass account creation
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit each IP to 3 registration requests per hour
  message: {
    error: "Too many accounts created from this IP, please try again after an hour."
  }
});

// General API rate limiter - protects against DoS attacks
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    error: "Too many requests from this IP, please try again later."
  }
});

// Strict rate limiter for sensitive endpoints
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 requests per windowMs
  message: {
    error: "Too many requests to this endpoint, please try again later."
  }
});

/////////////////////////////////////////////////////////////////////////middleware to verify token//////////////////////////////////////////////////
const verifyToken = (req, res, next) => {
  const token = req.cookies.token; // Access token from cookies

  console.log('Token from cookies:', token); // Debug log

  if (!token) {
    return res.status(403).json({ message: 'No token provided.' });
  }

  jwt.verify(token, process.env.LOGIN_KEY, (err, decoded) => {
    if (err) {
      console.error('Invalid token:', err);
      return res.status(401).json({ message: 'Invalid token.' });
    }
    req.user = decoded; // Store decoded token information in req.user
    next();
  });
};

const storage = multer.memoryStorage(); // Use memory storage for simplicity
const upload = multer({ storage: storage });

/////////////////////////////////////////////////////////////////////// DB connection is established///////////////////////////////////////////////
// Test database connection
(async () => {
    try {
        const connection = await db.getConnection();
        console.log('Connected to the database');
        connection.release();
    } catch (err) {
        console.error('Error connecting to the database:', err);
        process.exit(1);
    }
})(); 

/////////////////////////////////////////////////////////// Endpoint to handle GET request//////////////////////////////////////////////////////////
app.get('/', (req, res) => {
    return res.json("From Backend Side!");
});

// Apply general API rate limiting to all routes
app.use(apiLimiter);

//async for using try catch function
///////////////////////////////////////////////////////////////////////////// Login route/////////////////////////////////////////////////////////////
app.post('/Login', loginLimiter, async (req, res) => {
    const { email, password, ic, userType } = req.body;
    console.log("Request Received Login", req.body);

    // Input validation based on userType
    if (userType === "Admin") {
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required for Admin login.' });
        }
    } else if (userType === "users") {
        if (!ic || !password) {
            return res.status(400).json({ message: 'IC and password are required for User login.' });
        }
    } else {
        return res.status(400).json({ message: 'Invalid user type.' });
    }

    try {
        let query;
        let parameter;

        // Determine query and parameter based on userType
        if (userType === "Admin") {
            query = "SELECT * FROM admin WHERE email = ?";
            parameter = [email];
        } else {
            query = "SELECT * FROM users WHERE ic = ?";
            parameter = [ic];
        }

        // Execute database query
        const [results] = await db.query(query, parameter);

        if (results.length === 0) {
            return res.status(401).json({ message: 'No user found!' });
        }

        const user = results[0]; // Use the first user found in the database

        // Compare password with the hashed password in the database
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Incorrect password' });
        }

        // Create a JSON Web Token (JWT) for authenticated users
        const token = jwt.sign(
            { id: user.id, email: user.email || user.ic, userType: userType },
            process.env.LOGIN_KEY,
            { expiresIn: '1h' }
        );

        // Set the JWT as an HttpOnly cookie
        res.cookie('token', token, {
            httpOnly: true,                       // Prevents client-side JavaScript access
            secure: process.env.NODE_ENV === 'production', // Only send over HTTPS in production
            sameSite: 'strict',                   // Strictly same-site to avoid CSRF
            maxAge: 3600000                       // Cookie expiration set to 1 hour
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
    } catch (error) {
        console.error('Error during login:', error);
        return res.status(500).json({ message: 'Server error', error: error.message });
    }
});

///////////////////////////////////////////////////////////////////// check-account-exist endpoint////////////////////////////////////////////////
app.post('/check-account-exist', strictLimiter, async (req, res) => {
    const { username, email, ic, userType } = req.body;

    try {
        if(userType === "Admin"){
            const emailQuery = "SELECT * FROM admin WHERE email = ?";
            const [emailResults] = await db.query(emailQuery, [email]);

            if (emailResults.length > 0) {
                return res.json({ message: 'An account already exists with this email.' });
            }

            const usernameQuery = "SELECT * FROM admin WHERE username = ?";
            const [usernameResults] = await db.query(usernameQuery, [username]);

            if (usernameResults.length > 0) {
                // Return a 409 Conflict status for an existing IC
                return res.status(409).json({ message: 'An account already exists with this email.' });
            }

            // If no existing account with IC, allow creation
            return res.json({ message: 'No existing account with this email or username.' });
        } else if(userType === "users"){
            const icQuery = "SELECT * FROM users WHERE ic = ?";
            const [icResults] = await db.query(icQuery, [ic]);
            
            if (icResults.length > 0) {
                 // Return a 409 Conflict status for an existing IC
                return res.status(409).json({ message: 'An account already exists with this IC.' });
            }

            // If no existing account with IC, allow creation
            return res.json({message: "No existing account with this IC."});
        } else {
            return res.status(400).json({ message: 'Invalid user type.' });
        }
    } catch (err) {
        console.error('Database error:', err);
        return res.status(500).json({ message: 'Error checking account existence.' });
    }
});

/////////////////////////////////////////////////////////////////////////////// Register endpoint///////////////////////////////////////////////////
app.post('/register', registerLimiter, async (req, res) => {
    console.log('Received request:', req.body);  // Log the request body
    const { username, email, password, ic, userType} = req.body;

    if(userType === "Admin"){
        if (!username || !email || !password || password.length < 6) {
            return res.status(400).json({ message: 'All fields are required and password must be at least 6 characters long.' });
        }
    }else{
        if(!ic || !password || password.length < 6) {
            return res.status(400).json({ message: 'All fields are required and password must be at least 6 characters long.' });
        }
    }
    
    try {
        const saltRounds = 10; // Typically a value between 10 and 12
        // Generate salt and hash the password
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        let parameter;
        let query; 

        //differentiate user and admin and save to different database 
        if(userType === "Admin"){
            query = "INSERT INTO admin (email, username, password) VALUES (?, ?, ?)";
            parameter = [email, username, hashedPassword];
        } else if(userType === "users"){
            query = "INSERT INTO users (IC, password) VALUES (?, ?)";
            parameter = [ic, hashedPassword];
        }else{
            return res.status(400).json({ message: 'Invalid user type.' });
        }
           
        const [data] = await db.query(query, parameter);

        if (data.affectedRows > 0) {
            console.log('signup successful', req.body);
            return res.json({ message: "Sign Up Successful" });
        }
        return res.json({ message: "Sign Up unsuccessfully", data: data });
    } catch (error) {
        console.error('Error during registration:', error);
        return res.status(500).json({ message: 'Error !!', error: error.message });
    }
});

/////////////////////////////////////////////////////////////logout//////////////////////////////////////////////////
app.post('/logout', (req, res) =>{
    // Clear the JWT cookie by setting it to an expired date
    console.log(req.body);
    
    res.clearCookie('token',{
        httpOnly: true,// Ensures the cookie can't be accessed by JavaScript
        secure: process.env.NODE_ENV === 'production', // Ensures the cookie is only sent over HTTPS in production
        sameSite: 'strict', // SameSite policy to prevent CSRF attacks
    });
     // Send a response indicating the user is logged out
    return res.json({ message: 'Logged out successfully' });
});

const uploadToImgBB = async (imageBase64) => {
    try {
        const form = new FormData();
        form.append('key', process.env.IMGBB_API_KEY);
        form.append('image', imageBase64); // Base64 string without prefixes

        const response = await axios.post('https://api.imgbb.com/1/upload', form, {
            headers: form.getHeaders(),
            maxBodyLength: Infinity, // To handle large images
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
app.post('/updateUploadAttempt', verifyToken, strictLimiter, async (req, res) => {
    const userId = req.user.id;
    const uploadAttemptId = req.body.uploadAttemptId;
    
    try {
        const [result] = await db.query('UPDATE users SET upload_attempts = ? WHERE id = ?', [uploadAttemptId, userId]);
        res.status(200).send('Upload attempt updated successfully');
    } catch (err) {
        console.error('Database error:', err);
        return res.status(500).send('Error updating upload attempt');
    }
});

//////////////////////////////////////////////////////////////////fetch upload attempts/////////////////////////////////////////////////////////////
app.get('/getUploadAttempts', verifyToken, async (req, res) => {
    const userId = req.user.id;  

    const query = 'SELECT upload_attempts FROM users WHERE id = ?';

    try {
        const [results] = await db.query(query, [userId]);

        console.log('Query result:', results);  // Log query result to see its structure

        if (results && results.length > 0) {
            // Handle null value for upload_attempts
            const uploadAttempts = results[0].upload_attempts;
            res.status(200).json({ uploadAttempts });
        } else {
            res.status(404).json({ message: 'No data found for this user' });
        }
    } catch (err) {
        console.error('Error in query', err);
        return res.status(500).json({ message: 'Error retrieving upload attempts', error: err });
    }
});

/////////////////////////////////////////////////// Photo Upload Endpoint///////////////////////////////////////////////
app.post('/uploadImage', upload.single('file'), verifyToken, strictLimiter, async (req, res) => {
    console.log("File Upload Request:", req.file);
    const userId = req.user.id; // Retrieve userId from the decoded token

    if (!req.file) {
        return res.status(400).json({ message: 'Image file is required.' });
    }

    // Ensure the uploaded file is an image
    const validMimeTypes = ['image/jpeg', 'image/png', 'image/jpg'];
    if (!validMimeTypes.includes(req.file.mimetype)) {
        return res.status(400).json({ message: 'Invalid file type. Only JPG, PNG are allowed.' });
    }

    // Convert buffer to base64
    const imageBuffer = req.file.buffer; // Get the buffer directly from req.file
    const imageBase64 = imageBuffer.toString('base64');
    const imageContentType = req.file.mimetype;

    // Log the base64 string length and prefix for debugging
    console.log('Image Base64 Length:', imageBase64.length);
    console.log('Image Base64 Prefix:', imageBase64.substring(0, 30));

    const query = 'UPDATE users SET images = ?, image_content_type = ? WHERE id = ?';
    
    try {
        const [result] = await db.query(query, [imageBase64, imageContentType, userId]);

        if (result.affectedRows > 0) {
            return res.json({ message: 'Image updated successfully' });
        } else {
            return res.status(404).json({ message: 'User not found' });
        }
    } catch (err) {
        console.error('Database error while updating image:', err);
        return res.status(500).json({ message: 'Database error', error: err.message });
    }
});

/////////////////////////////////////////////////////////// Compare Faces Endpoint//////////////////////////////////////
app.post('/compareFaces', verifyToken, strictLimiter, async (req, res) => {
    console.log('User object:', req.user);
    const { capturedImage } = req.body;
    const userId = req.user.id;

    // Ensure capturedImage is received
    if (!capturedImage) {
        return res.status(400).json({ message: 'No captured image provided.' });
    }

    try {
        // Retrieve the stored image for the user from MySQL
        const query = 'SELECT images FROM users WHERE id = ?';
        const [results] = await db.query(query, [userId]);

        if (results.length === 0) {
            console.error('User image not found for user ID:', userId);
            return res.status(404).json({ message: 'User image not found.' });
        }

        const storedImageBase64 = results[0].images;

        // Log the stored image base64 string
        console.log('Stored Image Base64 Length:', storedImageBase64.length);
        console.log('Stored Image Base64 Prefix:', storedImageBase64.substring(0, 30));

        // Ensure images are present
        if (!storedImageBase64 || !capturedImage) {
            console.error('One or both images are missing.');
            return res.status(400).json({ message: 'Invalid image data.' });
        }

        // Upload stored image to ImgBB
        const storedImageUrl = await uploadToImgBB(storedImageBase64);
        if (!storedImageUrl) {
            return res.status(500).json({ message: 'Failed to upload stored image to ImgBB.' });
        }

        // Upload captured image to ImgBB
        const capturedImageUrl = await uploadToImgBB(capturedImage);
        if (!capturedImageUrl) {
            return res.status(500).json({ message: 'Failed to upload captured image to ImgBB.' });
        }

        // Verify that the URLs are accessible
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

        // Prepare data for Face++ API using image URLs
        const faceData = querystring.stringify({
            api_key: process.env.FACE_API_KEY,
            api_secret: process.env.FACE_API_SECRET,
            image_url1: storedImageUrl,
            image_url2: capturedImageUrl,
        });

        console.log('Sending data to Face++:', faceData);

        // Make POST request to Face++ API
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

//////////////////////////////////////////////Save Location/////////////////////////////////////////////////////////
app.post('/saveLocation', verifyToken, strictLimiter, async (req, res) => {
    const { capturedLatitude, capturedLongitude, selectedLatitude, selectedLongitude, selectedAddress } = req.body;
    const userId = req.user.id;

    console.log('Endpoint reached'); // Test log

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
        await db.query(query, [userId, capturedLatitude, capturedLongitude, selectedLatitude, selectedLongitude, selectedAddress]);
        res.status(200).send('Location saved successfully');
    } catch (error) {
        console.error('Error saving location:', error.message || error);
        res.status(500).send('Error saving location');
    }
});

///////////////////////////////////////////////////////////////////////Endpoint to save status in the users table///////////////////////////////////
app.post('/saveStatus', verifyToken, strictLimiter, async (req, res) => {
    const { status } = req.body;
    const userId = req.user.id;  // userId is obtained from the token

    if (!status) {
        return res.status(400).json({ message: 'Status is required' });
    }

    const query = `UPDATE users SET status = ? WHERE id = ?`;

    try {
        await db.query(query, [status, userId]);
        res.status(200).json({ message: 'Status updated successfully' });
    } catch (error) {
        console.error('Error updating status:', error.message || error);
        res.status(500).json({ message: 'Error updating status' });
    }
});

///////////////////////////////////////////////////// Endpoint to save reason in the users table////////////////////////////////
app.post('/saveReason', verifyToken, strictLimiter, async (req, res) => {
    const { reason } = req.body;
    const userId = req.user.id;  // userId is obtained from the token

    if (!reason) {
        return res.status(400).json({ message: 'Reason is required' });
    }

    const query = `UPDATE users SET reason = ? WHERE id = ?`;

    try {
        await db.query(query, [reason, userId]);
        res.status(200).json({ message: 'Reason updated successfully' });
    } catch (error) {
        console.error('Error updating reason:', error.message || error);
        res.status(500).json({ message: 'Error updating reason' });
    }
});
    
/////////////////////////////////////RETRIVE USERS DATABASE INTO ADMIN//////////////////////////////////
// Define a route to fetch data (example: fetching all users)
app.get('/users', verifyToken, async (req, res) => {
    const query = 'SELECT * FROM users';
    
    try {
        const [results] = await db.query(query);
        res.json(results);
        console.log(`result: ${results}`);
    } catch (error) {
        console.error('Error retrieving users:', error);
        res.status(500).json({ error: 'Failed to retrieve users' });
    }
});

//////////////////////////////////////////////////////////////////Delete user route////////////////////////////////////////////////////////////
app.delete('/users/:id', verifyToken, strictLimiter, async (req, res) => {
    const userId = req.params.id;
    const deleteQuery = 'DELETE FROM users WHERE id = ?';

    try {
        const [result] = await db.query(deleteQuery, [userId]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        return res.status(500).json({ error: 'Failed to delete user' });
    }
});

////////////////////////////////////////////////////////////Edit users information////////////////////////////////////
app.put('/users/:userId', verifyToken, strictLimiter, async (req, res) => {
    const userId = req.params.userId;
    const { ic, status, reason, selected_address, selected_latitude, selected_longitude } = req.body;

    try {
        await db.query(
            `UPDATE users SET ic = ?, status = ?, reason = ?, selected_address = ?, selected_latitude = ?, selected_longitude = ? WHERE id = ?`, 
            [ic, status, reason, selected_address, selected_latitude, selected_longitude, userId]
        );

        const [results] = await db.query(`SELECT * FROM users WHERE id = ?`, [userId]);

        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const updatedUser = results[0];
        res.status(200).json(updatedUser);
    } catch (err) {
        console.error('Error updating user:', err);
        return res.status(500).json({ error: 'Failed to update user' });
    }
});

// Start the server
const PORT = 8081;
app.listen(PORT, () => {
    console.log(`connected to database on port ${PORT}`);
});