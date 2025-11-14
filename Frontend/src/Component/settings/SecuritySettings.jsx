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
                // For regular users, get from upload attempts endpoint
                const response = await axios.get('http://localhost:8081/getUploadAttempts', {
                    withCredentials: true,
                });

                if (response.status === 200 && response.data.userId) {
                    setUserId(response.data.userId);
                    setUserType('users');
                }
            } catch (error) {
                console.log('Not a regular user, checking if admin...');
                setUserId(1);
                setUserType('Admin');
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
