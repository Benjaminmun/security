
import './login.css';
import React, { useState } from 'react';
import axios from 'axios';

// route
import { Link } from 'react-router-dom';

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

    // Default admin credentials
    const defaultAdmin = {
        email: "admin@gmail.com",
        password: "admin123@"
    };

    const handleUserTypeSelect = (type) => {
        setUserType(type);
        setShowLoginForm(true);
    };

    const handleSubmit = async (event) => {
        event.preventDefault();
        setLoginStatus(''); // Clear previous login status

        // Check if the credentials match the default admin account
        if (userType === 'Admin' && email === defaultAdmin.email && password === defaultAdmin.password) {
            window.confirm('Login successful as Admin');
            setTimeout(() => {
                window.location.href = '/adminhomepage';
            }, 2000);
            return;
        }

        try {
            // If not using default credentials, proceed with database check
            const response = await axios.post('http://localhost:8081/Login', {
                password,
                userType,
                ...(userType === "users" ? { ic } : { email })
            }, {
                withCredentials: true // Enable credentials for cookies
            });

            if (response.status === 200) {
                window.confirm('Login successful');
                setTimeout(() => {
                    if (userType === 'users') {
                        window.location.href = '/homepage';
                    } else {
                        window.location.href = '/adminhomepage';
                    }
                }, 2000);
            }
        } catch (error) {
            setLoginStatus('Login failed. Please try again.');
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
                        <div className='radio-group'>
                            <label className='radio'>
                                <input
                                    type="radio"
                                    name="userType"
                                    id="user"
                                    value="users"
                                    onChange={(e) => setUserType(e.target.value)}
                                    checked={userType === "users"}
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
                                            type="email"
                                            id="email"
                                            placeholder="Email"
                                            value={email}
                                            required
                                            onChange={(e) => setEmail(e.target.value)}
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
                                />
                                <div onClick={() => setVisible(!visible)}>
                                    {visible ? <MdVisibility id="password-visible" /> : <AiFillEyeInvisible id="password-visible" />}
                                </div>
                            </div>

                            {loginStatus && <span className="status">{loginStatus}</span>}
                        </div>

                        <button type="submit" className='btn'>
                            <span>Login</span>
                        </button>

                        <div className="footerDiv">
                            <span>Don't have an account?</span>
                            <Link to='/register'> Sign Up</Link>
                        </div>
                    </form>
                )}
            </div>
        </div>
    );
}

export default LoginPage;
