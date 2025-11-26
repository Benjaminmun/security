// React imports and CSS
import './register.css';
import { checkAccountExists, registerUser } from './register_service';
import { arePasswordsMatching, isPasswordValid, isValidIC } from './register_validation';
import React, { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { FaUserShield } from "react-icons/fa";
import { BsFillShieldLockFill } from "react-icons/bs";
import { AiFillEyeInvisible } from "react-icons/ai";
import { MdVisibility } from "react-icons/md";

function Register() {
    const [username, setUsername] = useState('');
    const [ic, setUserIc] = useState('');
    const [password, setPassword] = useState('');
    const [passwordVisible, setPasswordVisible] = useState(false);
    const [confirmPassword, setConfirmPassword] = useState('');
    const [confirmPasswordVisible, setConfirmPasswordVisible] = useState(false);
    const [registerStatus, setRegisterStatus] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [countdown, setCountdown] = useState(null);

    // Password and Confirm Password refs for validation
    const passwordRef = useRef(null);
    const passwordMessageRef = useRef(null);
    const passwordStrengthRef = useRef(null);
    const passwordProgressRef = useRef(null);
    const confirmPasswordRef = useRef(null);
    const confirmPasswordMessageRef = useRef(null);
    const confirmPasswordStrengthRef = useRef(null);
    const confirmPasswordProgressRef = useRef(null);

    useEffect(() => {
        const handleInput = (event) => {
            const { target } = event;
            const value = target.value;
            const isPasswordField = target === passwordRef.current;
            const messageRef = isPasswordField ? passwordMessageRef : confirmPasswordMessageRef;
            const strengthRef = isPasswordField ? passwordStrengthRef : confirmPasswordStrengthRef;
            const progressRef = isPasswordField ? passwordProgressRef : confirmPasswordProgressRef;

            if (!messageRef.current || !strengthRef.current || !progressRef.current) return;

            if (!value) {
                messageRef.current.style.display = "none";
                strengthRef.current.innerHTML = "";
                progressRef.current.style.width = "0%";
                return;
            }

            messageRef.current.style.display = "block";

            const hasMinLength = value.length >= 8;
            const hasUppercase = /[A-Z]/.test(value);
            const hasLowercase = /[a-z]/.test(value);
            const hasNumber = /\d/.test(value);
            const hasSymbol = /[^A-Za-z0-9]/.test(value);
            const metCount = [hasMinLength, hasUppercase, hasLowercase, hasNumber, hasSymbol].filter(Boolean).length;

            let strength = "weak";
            let color = "#ff5925";

            if (metCount >= 5) {
                strength = "strong";
                color = "#26d730";
            } else if (metCount >= 3) {
                strength = "medium";
                color = "#FFA500";
            }

            strengthRef.current.innerHTML = strength;
            messageRef.current.style.color = color;
            progressRef.current.style.width = `${(metCount / 5) * 100}%`;
            progressRef.current.style.backgroundColor = color;
        };

        const currentPasswordRef = passwordRef.current;
        const currentConfirmPasswordRef = confirmPasswordRef.current;

        if (currentPasswordRef) {
            currentPasswordRef.addEventListener('input', handleInput);
        }
        if (currentConfirmPasswordRef) {
            currentConfirmPasswordRef.addEventListener('input', handleInput);
        }

        return () => {
            if (currentPasswordRef) {
                currentPasswordRef.removeEventListener('input', handleInput);
            }
            if (currentConfirmPasswordRef) {
                currentConfirmPasswordRef.removeEventListener('input', handleInput);
            }
        };
    }, []);

    // Countdown timer for rate limiting
    const startCountdown = (seconds) => {
        setCountdown(seconds);
        const timer = setInterval(() => {
            setCountdown(prev => {
                if (prev <= 1) {
                    clearInterval(timer);
                    setRegisterStatus('You can now try registering again.');
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

    // Enhanced error handler for rate limiting - FIXED VERSION
    const handleRateLimitError = (error, operationType) => {
        if (error.response && error.response.status === 429) {
            const responseData = error.response.data;
            // Use retryAfter from backend response, fallback to 3600 seconds (1 hour)
            const retryAfter = responseData.retryAfter || 3600;
            const waitMinutes = Math.ceil(retryAfter / 60);
            
            const message = operationType === 'check' 
                ? `Too many account checks. Please try again in ${waitMinutes} minute(s).`
                : `Too many registration attempts. Please try again in ${waitMinutes} minute(s).`;
            
            setRegisterStatus(message);
            startCountdown(retryAfter); // ← THIS WAS MISSING - NOW ADDED!
            return true; // Indicates rate limit was handled
        }
        return false;
    };

    const handleSubmit = async (event) => {
        event.preventDefault();
        setIsLoading(true);
        setRegisterStatus('');
        setCountdown(null);

        // Basic validations
        if (!arePasswordsMatching(password, confirmPassword)) {
            setRegisterStatus('Passwords do not match.');
            setIsLoading(false);
            return;
        }

        if (!isPasswordValid(password)) {
            setRegisterStatus('Password must be at least 8 characters and include uppercase, lowercase, number, and symbol.');
            setIsLoading(false);
            return;
        }

        if (!isValidIC(ic)) {
            setRegisterStatus('Invalid IC format. Please use XXXXXX-XX-XXXX format.');
            setIsLoading(false);
            return;
        }

        // Check if account exists
        try {
            const response = await checkAccountExists(username, ic);
            const existUsername = 'An account already exists with this username.';
            const existIC = 'An account already exists with this IC.';

            if (response.message === existUsername || response.message === existIC) {
                setRegisterStatus('An account already exists!');
                setIsLoading(false);
                return;
            }
        } catch (error) {
            // Handle rate limiting for account check
            if (handleRateLimitError(error, 'check')) {
                setIsLoading(false);
                return;
            }
            
            // Handle other errors
            if (error.response && error.response.status === 400) {
                const errorMessage = error.response.data.message || 'Invalid input';
                
                if (errorMessage.includes('SQL injection') ||
                    errorMessage.includes('Invalid characters') || 
                    errorMessage.includes('injection')) {
                    setRegisterStatus('🛡️ SECURITY: Suspicious input detected and blocked. SQL injection attempt prevented.');
                } else if (errorMessage.includes('IC')) {
                    setRegisterStatus('🛡️ SECURITY: Invalid IC format. Please use YYMMDD-PB-###G format.');
                } else if (errorMessage.includes('email')) {
                    setRegisterStatus('🛡️ SECURITY: Invalid email format detected.');
                } else if (errorMessage.includes('username')) {
                    setRegisterStatus('🛡️ SECURITY: Invalid username. Use only letters, numbers, and underscores.');
                } else {
                    setRegisterStatus('🛡️ SECURITY: ' + errorMessage);
                }
            } else {
                setRegisterStatus('Error checking account existence: ' + (error.message || 'Unknown error'));
            }
            setIsLoading(false);
            return;
        }

        // Register user
        try {
            const response = await registerUser(username, ic, password);
            if (response.message === 'Sign Up Successful') {
                setRegisterStatus('Registration successful! Redirecting to login...');
                setTimeout(() => {
                    window.location.href = '/login';
                }, 2000);
            }
        } catch (error) {
            // Handle rate limiting for registration
            if (handleRateLimitError(error, 'register')) {
                setIsLoading(false);
                return;
            }
            
            // Handle other registration errors
            if (error.response && error.response.status === 400) {
                const errorMessage = error.response.data.message || 'Invalid input';
                
                if (errorMessage.includes('SQL injection') ||
                    errorMessage.includes('Invalid characters') || 
                    errorMessage.includes('injection')) {
                    setRegisterStatus('🛡️ SECURITY: Suspicious input detected and blocked. SQL injection attempt prevented.');
                } else if (errorMessage.includes('Password')) {
                    setRegisterStatus('🛡️ SECURITY: ' + errorMessage);
                } else if (errorMessage.includes('IC')) {
                    setRegisterStatus('🛡️ SECURITY: Invalid IC format. Please use YYMMDD-PB-###G format.');
                } else if (errorMessage.includes('username')) {
                    setRegisterStatus('🛡️ SECURITY: Invalid username. Use only letters, numbers, and underscores.');
                } else {
                    setRegisterStatus('🛡️ SECURITY: ' + errorMessage);
                }
            } else {
                setRegisterStatus('Registration failed: ' + (error.message || 'Unknown error'));
            }
            setIsLoading(false);
            return;
        }
        
        setIsLoading(false);
    };

    const togglePasswordVisibility = () => {
        if (!isLoading && !countdown) setPasswordVisible(!passwordVisible);
    };

    const toggleConfirmPasswordVisibility = () => {
        if (!isLoading && !countdown) setConfirmPasswordVisible(!confirmPasswordVisible);
    };

    return (
        <div className='loginPage'>
            <div className="container">
                <div className="headerDiv">
                    <h2 style={{ fontWeight: 'bold' }}>User Registration</h2>
                </div>
                <form onSubmit={handleSubmit} className='form'>

                    <div className="inputDiv">
                        <label htmlFor="IC">IC:</label>
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

                    <div className="inputDiv">  
                        <label htmlFor="password">Password:</label>
                        <div className="input flex">
                            <BsFillShieldLockFill className='icon' />
                            <input
                                type={passwordVisible ? "text" : "password"}
                                id="password"
                                ref={passwordRef}
                                placeholder="Password"
                                value={password}
                                required
                                onChange={(e) => setPassword(e.target.value)}
                                disabled={isLoading || countdown}
                            />
                            <div onClick={togglePasswordVisibility} style={{ cursor: (isLoading || countdown) ? 'not-allowed' : 'pointer' }}>
                                {passwordVisible ? <MdVisibility id="password-visible" /> : <AiFillEyeInvisible id="password-visible" />}
                            </div>
                        </div>
                        <div className="passwordFeedback">
                            <div className="passwordStrengthBar">
                                <div className="passwordStrengthFill" ref={passwordProgressRef}></div>
                            </div>
                            <p className="passwordMessage" ref={passwordMessageRef}>
                                Password is <span className="passwordStrength" ref={passwordStrengthRef}></span>
                            </p>
                            <p className='passwordRequirements'>
                                Use at least 8 characters, including uppercase, lowercase, a number, and a symbol.
                            </p>
                        </div>
                    </div>

                    <div className="inputDiv">
                        <label htmlFor="confirmPassword">Confirm Password:</label>
                        <div className="input flex">
                            <BsFillShieldLockFill className='icon' />
                            <input
                                type={confirmPasswordVisible ? "text" : "password"}
                                id="confirmPassword"
                                placeholder="Confirm password"
                                ref={confirmPasswordRef}
                                value={confirmPassword}
                                required
                                onChange={(e) => setConfirmPassword(e.target.value)}
                                disabled={isLoading || countdown}
                            />
                            <div onClick={toggleConfirmPasswordVisibility} style={{ cursor: (isLoading || countdown) ? 'not-allowed' : 'pointer' }}>
                                {confirmPasswordVisible ? <MdVisibility id="password-visible" /> : <AiFillEyeInvisible id="password-visible" />}
                            </div>
                        </div>
                        <div className="passwordFeedback">
                            <div className="passwordStrengthBar">
                                <div className="passwordStrengthFill" ref={confirmPasswordProgressRef}></div>
                            </div>
                            <p className="passwordMessage" ref={confirmPasswordMessageRef}>
                                Password is <span className="passwordStrength" ref={confirmPasswordStrengthRef}></span>
                            </p>
                        </div>
                    </div>

                    {registerStatus && (
                        <div className={`status ${registerStatus.includes('successful') ? 'success' : 'error'}`}>
                            {registerStatus}
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

                    <div className="button">
                        <button 
                            type="submit" 
                            className='btn' 
                            disabled={isLoading || countdown}
                        >
                            <span>
                                {isLoading ? 'Registering...' : 
                                 countdown ? `Please wait (${formatTime(countdown)})` : 
                                 'Sign Up'}
                            </span>
                        </button>
                    </div>

                    <div className="footer">
                        <p>Already have an account? <Link to="/login">Login</Link></p>
                    </div>

                    {/* Rate Limit Information */}
                    <div style={{ 
                        marginTop: '1rem', 
                        padding: '0.5rem', 
                        backgroundColor: '#f8f9fa', 
                        borderRadius: '4px',
                        fontSize: '12px',
                        color: '#6c757d',
                        textAlign: 'center'
                    }}>
                        <strong>Registration Limits:</strong><br />
                        • Maximum 3 registrations per hour per IP address<br />
                        • Accounts are checked for duplicates automatically
                    </div>
                </form>
            </div>
        </div>
    );
}

export default Register;