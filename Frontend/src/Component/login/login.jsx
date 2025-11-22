import './login.css';
import React, { useState } from 'react';
import axios from 'axios';

// route
import { Link } from 'react-router-dom';
import { startActivityWatcher } from "../../utils/activityWatcher"; 

// icons
import { FaUserShield } from "react-icons/fa";
import { FaUser, FaShieldAlt } from "react-icons/fa";
import { BsFillShieldLockFill } from "react-icons/bs";
import { AiFillEyeInvisible } from "react-icons/ai";
import { MdVisibility } from "react-icons/md";

function LoginPage() {
    const [email, setEmail] = useState('');
    const [ic, setUserIc] = useState('');
    const [password, setPassword] = useState('');
    const [visible, setVisible] = useState(false);
    const [loginStatus, setLoginStatus] = useState('');
    const [userType, setUserType] = useState('');
    const [showLoginForm, setShowLoginForm] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [countdown, setCountdown] = useState(null);

    // Default admin credentials
    const defaultAdmin = {
        email: "admin@gmail.com",
        password: "admin123@"
    };

    const handleUserTypeSelect = (type) => {
        setUserType(type);
        setShowLoginForm(true);
        setLoginStatus('');
        setCountdown(null);
    };

    const handleBackToSelection = () => {
        setShowLoginForm(false);
        setUserType('');
        setEmail('');
        setUserIc('');
        setPassword('');
        setLoginStatus('');
        setCountdown(null);
    };

    // Countdown timer for rate limiting
    const startCountdown = (seconds) => {
        setCountdown(seconds);
        const timer = setInterval(() => {
            setCountdown(prev => {
                if (prev <= 1) {
                    clearInterval(timer);
                    setLoginStatus('You can now try logging in again.');
                    return null;
                }
                return prev - 1;
            });
        }, 1000);
    };

    const formatTime = (seconds) => {
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = seconds % 60;
        return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
    };

    const handleSubmit = async (event) => {
        event.preventDefault();
        setIsLoading(true);
        setLoginStatus('');
        setCountdown(null);

        // Check if the credentials match the default admin account


        try {
            // If not using default credentials, proceed with database check
            const response = await axios.post('http://localhost:8081/Login', {
                password,
                userType,
                ...(userType === "users" ? { ic } : { email })
            }, {
                withCredentials: true,
                timeout: 10000
            });

            if (response.status === 200) {
                startActivityWatcher();
                setTimeout(() => {
                    setIsLoading(false);
                    window.confirm('Login successful');
                    if (userType === 'users') {
                        window.location.href = '/homepage';
                    } else {
                        window.location.href = '/adminhomepage';
                    }
                }, 1000);
            }
        } catch (error) {
            setIsLoading(false);
            
            if (error.response) {
                const status = error.response.status;
                const responseData = error.response.data;
                
                if (status === 429) {
                    // Rate limit exceeded - show precise wait time
                    const retryAfter = responseData.retryAfter || 900; // Default to 15 minutes
                    const waitMinutes = Math.ceil(retryAfter / 60);
                    
                    setLoginStatus(`Too many attempts. Please try again in ${waitMinutes} minute(s).`);
                    startCountdown(retryAfter);
                    
                } else if (status === 423) {
                    // Account locked
                    const retryAfter = responseData.retryAfter;
                    if (retryAfter) {
                        setLoginStatus(`Account temporarily locked. Please try again in ${Math.ceil(retryAfter / 60)} minute(s).`);
                        startCountdown(retryAfter);
                    } else {
                        setLoginStatus('Account is locked. Please contact administrator.');
                    }
                    
                } else if (status === 401) {
                    setLoginStatus('Invalid credentials. Please check your email/IC and password.');
                } else if (status === 400) {
                    // SECURITY: Input Validation - Show specific error messages
                    const errorMessage = responseData.message || 'Invalid input. Please check your information.';
                    
                    // Check for specific security violations - ORDER MATTERS!
                    // Check SQL injection FIRST before other validations
                    if (errorMessage.includes('SQL injection') ||
                        errorMessage.includes('Invalid characters detected') || 
                        errorMessage.includes('injection')) {
                        setLoginStatus('🛡️ SECURITY: Suspicious input detected and blocked. SQL injection attempt prevented.');
                    } else if (errorMessage.includes('Invalid email format') || 
                        errorMessage.includes('email')) {
                        setLoginStatus('🛡️ SECURITY: Invalid email format detected. Please enter a valid email address.');
                    } else if (errorMessage.includes('Invalid IC') || 
                               errorMessage.includes('IC format')) {
                        setLoginStatus('🛡️ SECURITY: Invalid IC format detected. Please use format YYMMDD-PB-###G.');
                    } else if (errorMessage.includes('user type')) {
                        setLoginStatus('🛡️ SECURITY: Invalid user type. Please select Admin or User.');
                    } else {
                        setLoginStatus('🛡️ SECURITY: ' + errorMessage);
                    }
                } else if (status === 403) {
                    // SECURITY: Access Control - Unauthorized access
                    setLoginStatus('🛡️ SECURITY: Access denied. Insufficient permissions.');
                } else {
                    setLoginStatus('Login failed. Please try again.');
                }
            } else if (error.request) {
                setLoginStatus('Network error. Please check your connection.');
            } else {
                setLoginStatus('An unexpected error occurred.');
            }
            console.error('Login error:', error);
        }
    };

    return (
        <div className='loginPage'>
            <div className="container">
                <div className="headerDiv">
                    <h1>Login</h1>
                    <h2>Welcome Back!</h2>
                </div>

                {!showLoginForm ? (
                    <div>
                        <div className="userTypeSelectionButton">
                            <button className="btn big-button" onClick={() => handleUserTypeSelect('users')}>
                                <FaUser className="button-icon" />Log in as User
                            </button>
                            <button className="btn big-button" onClick={() => handleUserTypeSelect('Admin')}>
                                <FaShieldAlt className="button-icon" />Log in as Admin
                            </button>
                        </div>

                        <div className="footerDiv">
                            <span>Don't have an account?</span>
                            <Link to='/register'> Sign Up</Link>
                        </div>
                    </div>
                ) : (
                    <form onSubmit={handleSubmit} className='form'>
                        <button 
                            type="button" 
                            className="back-button" 
                            onClick={handleBackToSelection}
                            style={{
                                background: 'none',
                                border: 'none',
                                color: '#007bff',
                                cursor: 'pointer',
                                marginBottom: '1rem',
                                fontSize: '14px'
                            }}
                        >
                            ← Back to selection
                        </button>

                        <div className='radio-group'>
                            <label className='radio'>
                                <input
                                    type="radio"
                                    name="userType"
                                    id="user"
                                    value="users"
                                    onChange={(e) => setUserType(e.target.value)}
                                    checked={userType === "users"}
                                    disabled={isLoading || countdown}
                                /> Users
                                <span></span>
                            </label>
                            <label className='radio'>
                                <input
                                    type="radio"
                                    name="userType"
                                    id="admin"
                                    value="Admin"
                                    onChange={(e) => setUserType(e.target.value)}
                                    checked={userType === "Admin"}
                                    disabled={isLoading || countdown}
                                /> Admin
                                <span></span>
                            </label>
                        </div>

                        <>
                            {userType === "Admin" ? (
                                <div className="inputDiv">
                                    <label htmlFor="email">Email:</label>
                                    <div className="input flex">
                                        <FaUserShield className='icon' />
                                        <input
                                            type="text"
                                            id="email"
                                            placeholder="Email"
                                            value={email}
                                            required
                                            onChange={(e) => setEmail(e.target.value)}
                                            disabled={isLoading || countdown}
                                        />
                                    </div>
                                </div>
                            ) : (
                                <div className="inputDiv">
                                    <label htmlFor="ic">IC:</label>
                                    <div className="input flex">
                                        <FaUserShield className='icon' />
                                        <input
                                            type="text"
                                            id="ic"
                                            placeholder="IC"
                                            value={ic}
                                            required
                                            onChange={(e) => setUserIc(e.target.value)}
                                            disabled={isLoading || countdown}
                                        />
                                    </div>
                                </div>
                            )}
                        </>

                        <div className="inputDiv">
                            <label htmlFor="password">Password:</label>
                            <div className="input flex">
                                <BsFillShieldLockFill className='icon' />
                                <input
                                    type={visible ? "text" : "password"}
                                    id="password"
                                    placeholder="Password"
                                    value={password}
                                    required
                                    onChange={(e) => setPassword(e.target.value)}
                                    disabled={isLoading || countdown}
                                />
                                <div onClick={() => setVisible(!visible)} style={{cursor: 'pointer'}}>
                                    {visible ? <MdVisibility id="password-visible" /> : <AiFillEyeInvisible id="password-visible" />}
                                </div>
                            </div>

                            {loginStatus && (
                                <div className={`status ${loginStatus.includes('successful') ? 'success' : 'error'}`}>
                                    {loginStatus}
                                    {countdown && (
                                        <div style={{ 
                                            marginTop: '10px', 
                                            fontSize: '14px', 
                                            fontWeight: 'bold',
                                            color: '#ff6b6b'
                                        }}>
                                            Time remaining: {formatTime(countdown)}
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>

                        <button 
                            type="submit" 
                            className='btn' 
                            disabled={isLoading || countdown}
                        >
                            {isLoading ? 'Logging in...' : countdown ? `Please wait (${formatTime(countdown)})` : 'Login'}
                        </button>

                        <div className="footerDiv">
                            <span>Don't have an account?</span>
                            <Link to='/register'> Sign Up</Link>
                        </div>

                        {/* Rate Limit Information */}
                        <div style={{ 
                            marginTop: '1rem', 
                            padding: '0.5rem', 
                            backgroundColor: '#f8f9fa', 
                            borderRadius: '4px',
                            fontSize: '12px',
                            color: '#6c757d'
                        }}>
                            <strong>Rate Limits:</strong><br />
                            • 5 attempts per 15 minutes (IP-based)<br />
                            • 10 attempts per hour (account-based)<br />
                            • Accounts locked after 5 failed attempts in 30 minutes
                        </div>
                    </form>
                )}
            </div>
        </div>
    );
}

export default LoginPage;