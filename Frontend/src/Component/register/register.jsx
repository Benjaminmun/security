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

    const handleSubmit = async (event) => {
        event.preventDefault();

        if (!arePasswordsMatching(password, confirmPassword)) {
            setRegisterStatus('Passwords do not match.');
            return;
        }

        if (!isPasswordValid(password)) {
            setRegisterStatus('Password must be at least 8 characters and include uppercase, lowercase, number, and symbol.');
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
                            />
                            <div onClick={() => setConfirmPasswordVisible(!confirmPasswordVisible)}>
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
