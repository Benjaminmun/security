import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './TwoFactorVerify.css';

const TwoFactorVerify = ({ userId, userType, onCancel }) => {
    const [verificationCode, setVerificationCode] = useState('');
    const [useBackupCode, setUseBackupCode] = useState(false);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const handleVerify = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        try {
            const response = await axios.post(
                'http://localhost:8081/2fa/verify-login',
                {
                    userId,
                    userType,
                    token: verificationCode,
                    isBackupCode: useBackupCode
                },
                { withCredentials: true }
            );

            // Successful 2FA verification - redirect to appropriate page
            if (userType === 'Admin') {
                navigate('/adminhomepage');
            } else {
                navigate('/homepage');
            }
        } catch (err) {
            setError(err.response?.data?.message || 'Verification failed. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    const handleCodeChange = (e) => {
        const value = e.target.value;
        if (useBackupCode) {
            // Backup codes are alphanumeric, max 8 characters
            setVerificationCode(value.toUpperCase().slice(0, 8));
        } else {
            // TOTP codes are 6 digits
            setVerificationCode(value.replace(/\D/g, '').slice(0, 6));
        }
    };

    const toggleBackupCode = () => {
        setUseBackupCode(!useBackupCode);
        setVerificationCode('');
        setError('');
    };

    return (
        <div className="two-factor-verify-overlay">
            <div className="two-factor-verify-modal">
                <div className="verify-header">
                    <h2>Two-Factor Authentication</h2>
                </div>

                <div className="verify-body">
                    <p className="verify-instruction">
                        {useBackupCode
                            ? 'Enter one of your backup codes:'
                            : 'Enter the 6-digit code from your authenticator app:'}
                    </p>

                    {error && <div className="error-message">{error}</div>}

                    <form onSubmit={handleVerify}>
                        <input
                            type="text"
                            placeholder={useBackupCode ? 'Backup Code' : '000000'}
                            value={verificationCode}
                            onChange={handleCodeChange}
                            maxLength={useBackupCode ? 8 : 6}
                            className="verify-input"
                            autoFocus
                            required
                        />

                        <button
                            type="submit"
                            className="verify-submit-btn"
                            disabled={loading || verificationCode.length < (useBackupCode ? 6 : 6)}
                        >
                            {loading ? 'Verifying...' : 'Verify'}
                        </button>
                    </form>

                    <div className="verify-options">
                        <button className="toggle-backup-btn" onClick={toggleBackupCode}>
                            {useBackupCode
                                ? 'Use Authenticator Code'
                                : 'Use Backup Code'}
                        </button>

                        {onCancel && (
                            <button className="cancel-btn" onClick={onCancel}>
                                Cancel
                            </button>
                        )}
                    </div>

                    <div className="verify-help">
                        <p>Lost your authenticator device?</p>
                        <p>Use one of your backup codes to access your account.</p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default TwoFactorVerify;