import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import TwoFactorManagement from '../2fa/TwoFactorManagement';
import './SecuritySettings.css';

function SecuritySettings() {
    const navigate = useNavigate();
    const [userId, setUserId] = useState(null);
    const [userType, setUserType] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        // Fetch user information
        const fetchUserInfo = async () => {
            try {
                // NEW: Fetch logged-in user from JWT token
                const res = await axios.get("http://localhost:8081/auth/me", {
                    withCredentials: true,
                });

                setUserId(res.data.id);          // real ID from backend
                setUserType(res.data.userType);  // "Admin" or "users"
            } catch (error) {
                console.error("Failed to identify logged-in user", error);
            } finally {
                setLoading(false);
            }
        };

        fetchUserInfo();
    }, []);

    const handleBack = () => {
        if (userType === 'Admin') {
            navigate('/adminhomepage');
        } else {
            navigate('/homepage');
        }
    };

    if (loading) {
        return (
            <div className="security-settings-page">
                <div className="loading-container">
                    <p>Loading security settings...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="security-settings-page">
            <div className="security-settings-container">
                <div className="settings-header">
                    <button className="back-button" onClick={handleBack}>
                        ← Back
                    </button>
                    <h1>Security Settings</h1>
                </div>

                <div className="settings-content">
                    {userId && userType ? (
                        <TwoFactorManagement userId={userId} userType={userType} />
                    ) : (
                        <div className="error-message">
                            Unable to load user information. Please try logging in again.
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

export default SecuritySettings;