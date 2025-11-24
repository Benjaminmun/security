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
                // Use the /me endpoint to get authenticated user info
                const response = await axios.get('http://localhost:8081/auth/me', {
                    withCredentials: true,
                });

                if (response.status === 200 && response.data.id) {
                    setUserId(response.data.id);
                    setUserType(response.data.userType);
                }
            } catch (error) {
                console.error('Failed to fetch user information:', error);
                // Redirect to login if not authenticated
                navigate('/login');
            } finally {
                setLoading(false);
            }
        };

        fetchUserInfo();
    }, [navigate]);

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