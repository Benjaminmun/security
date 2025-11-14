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

    // Password and Confirm Password refs for validation
    const passwordRef = useRef(null);
    const passwordMessageRef = useRef(null);
    const passwordStrengthRef = useRef(null);
    const confirmPasswordRef = useRef(null);
    const confirmPasswordMessageRef = useRef(null);
    const confirmPasswordStrengthRef = useRef(null);

    useEffect(() => {
        const handleInput = (event) => {
            const { target } = event;
            const value = target.value;
            const hasSymbol = /[!@#$%^&*(),.?":{}|<>]/.test(value);
            const isPasswordField = target === passwordRef.current;
            const messageRef = isPasswordField ? passwordMessageRef : confirmPasswordMessageRef;
            const strengthRef = isPasswordField ? passwordStrengthRef : confirmPasswordStrengthRef;

            messageRef.current.style.display = value.length > 0 ? "block" : "none";

            if (value.length <= 5 || !hasSymbol) {
                strengthRef.current.innerHTML = "weak";
                messageRef.current.style.color = "#ff5925";
            } else if (value.length >= 6 && value.length < 8 && hasSymbol) {
                strengthRef.current.innerHTML = "medium";
                messageRef.current.style.color = "#FFA500";
            } else if (value.length >= 8 && hasSymbol) {
                strengthRef.current.innerHTML = "strong";
                messageRef.current.style.color = "#26d730";
            }
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

    const handleSubmit = async (event) => {
        event.preventDefault();

        if (!arePasswordsMatching(password, confirmPassword)) {
            setRegisterStatus('Passwords do not match.');
            return;
        }

        if (!isPasswordValid(password)) {
            setRegisterStatus('Password must be at least 6 characters.');
            return;
        }

        if (!isValidIC(ic)) {
            setRegisterStatus('Invalid IC format. Please use XXXXXX-XX-XXXX format.');
            return;
        }

        // Check if account exists
        try {
            const response = await checkAccountExists(username, ic);
            const existUsername = 'An account already exists with this username.';
            const existIC = 'An account already exists with this IC.';

            if (response.message === existUsername || response.message === existIC) {
                setRegisterStatus('An account already exists!');
                return;
            } else {
                window.confirm('Sign Up Successful');
            }
        } catch (error) {
            setRegisterStatus('Error checking account existence: ', error);
            return;
        }

        // Register user
        try {
            const response = await registerUser(username, ic, password);
            if (response.message === 'Sign Up Successful') {
                setTimeout(() => {
                    window.location.href = '/login';
                }, 2000);
            }
        } catch (error) {
            setRegisterStatus('Registration failed. Please try again.');
            return;
        }
    };

    return (
        <div className='loginPage'>
            <div className="container">
                <div className="headerDiv">
                <h2 style={{ fontWeight: 'bold' }}>User Registration</h2>
                </div>
                <form onSubmit={handleSubmit} className='form'>
                    <div className="inputDiv">
                </div>

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
                            />
                            <div onClick={() => setPasswordVisible(!passwordVisible)}>
                                {passwordVisible ? <MdVisibility id="password-visible" /> : <AiFillEyeInvisible id="password-visible" />}
                            </div>

                            <p id="message" ref={passwordMessageRef}>Password is <span id="strength" ref={passwordStrengthRef}></span></p>
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
                            />
                            <div onClick={() => setConfirmPasswordVisible(!confirmPasswordVisible)}>
                                {confirmPasswordVisible ? <MdVisibility id="password-visible" /> : <AiFillEyeInvisible id="password-visible" />}
                            </div>

                            <p id="message" ref={confirmPasswordMessageRef}>Password is <span id="strength" ref={confirmPasswordStrengthRef}></span></p>
                        </div>
                    </div>

                    <div className="status">
                        <p>{registerStatus}</p>
                    </div>

                    <div className="button">
                        <button type="submit" className='btn'>
                            <span>Sign Up</span>
                        </button>
                    </div>

                    <div className="footer">
                        <p>Already have an account? <Link to="/login">Login</Link></p>
                    </div>
                </form>
            </div>
        </div>
    );
}

export default Register;