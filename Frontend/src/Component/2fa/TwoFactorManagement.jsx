import React, { useState, useEffect } from 'react';
import axios from 'axios';
import TwoFactorSetup from './TwoFactorSetup';
import './TwoFactorManagement.css';

const TwoFactorManagement = ({ userId, userType }) => {
    const [is2FAEnabled, setIs2FAEnabled] = useState(false);
    const [showSetup, setShowSetup] = useState(false);
    const [showDisableConfirm, setShowDisableConfirm] = useState(false);
    const [verificationCode, setVerificationCode] = useState('');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');

    // Check 2FA status on component mount
    useEffect(() => {
        check2FAStatus();
    }, [userId, userType]);

    const check2FAStatus = async () => {
        setLoading(true);
        try {
            const response = await axios.get(
                `http://localhost:8081/2fa/status/${userId}/${userType}`,
                { withCredentials: true }
            );
            setIs2FAEnabled(response.data.twoFactorEnabled);
        } catch (err) {
            console.error('Error checking 2FA status:', err);
        } finally {
            setLoading(false);
        }
    };

    const handleEnable2FA = () => {
        setShowSetup(true);
        setError('');
        setSuccess('');
    };

    const handleSetupSuccess = () => {
        setShowSetup(false);
        setIs2FAEnabled(true);
        setSuccess('Two-factor authentication enabled successfully!');
        setTimeout(() => setSuccess(''), 5000);
    };

    const handleDisable2FA = async () => {
        if (!verificationCode || verificationCode.length !== 6) {
            setError('Please enter the 6-digit code from your authenticator app');
            return;
        }

        setLoading(true);
        setError('');

        try {
            await axios.post(
                'http://localhost:8081/2fa/disable',
                { userId, userType, token: verificationCode },
                { withCredentials: true }
            );

            setIs2FAEnabled(false);
            setShowDisableConfirm(false);
            setVerificationCode('');
            setSuccess('Two-factor authentication disabled successfully.');
            setTimeout(() => setSuccess(''), 5000);
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to disable 2FA');
        } finally {
            setLoading(false);
        }
    };

    const handleCancelDisable = () => {
        setShowDisableConfirm(false);
        setVerificationCode('');
        setError('');
    };

    if (loading && !showDisableConfirm) {
        return (
            <div className="two-factor-management">
                <div className="loading">Loading 2FA settings...</div>
            </div>
        );
    }

    return (
        <div className="two-factor-management">
            {showSetup && (
                <TwoFactorSetup
                    userId={userId}
                    userType={userType}
                    onClose={() => setShowSetup(false)}
                    onSuccess={handleSetupSuccess}
                />
            )}

            <div className="security-section">
                <div className="section-header">
                    <h3>Two-Factor Authentication (2FA)</h3>
                    <div className={`status-badge ${is2FAEnabled ? 'enabled' : 'disabled'}`}>
                        {is2FAEnabled ? 'Enabled' : 'Disabled'}
                    </div>
                </div>

                <p className="section-description">
                    Add an extra layer of security to your account. When enabled, you'll need to enter a code from your authenticator app when logging in.
                </p>

                {success && <div className="success-message">{success}</div>}
                {error && <div className="error-message">{error}</div>}

                {!is2FAEnabled ? (
                    <div className="action-container">
                        <button className="enable-btn" onClick={handleEnable2FA}>
                            Enable Two-Factor Authentication
                        </button>
                        <div className="info-box">
                            <strong>Benefits of 2FA:</strong>
                            <ul>
                                <li>Protects your account even if your password is compromised</li>
                                <li>Industry-standard security practice</li>
                                <li>Required for accounts with sensitive data access</li>
                            </ul>
                        </div>
                    </div>
                ) : (
                    <div className="action-container">
                        {!showDisableConfirm ? (
                            <>
                                <div className="status-info">
                                    <div className="check-icon">✓</div>
                                    <p>Your account is protected with two-factor authentication.</p>
                                </div>
                                <button
                                    className="disable-btn"
                                    onClick={() => setShowDisableConfirm(true)}
                                >
                                    Disable Two-Factor Authentication
                                </button>
                            </>
                        ) : (
                            <div className="disable-confirm-box">
                                <h4>Disable Two-Factor Authentication?</h4>
                                <p className="warning">
                                    This will make your account less secure. You'll only need your password to log in.
                                </p>
                                <div className="password-input-group">
                                    <label htmlFor="verification-code">Enter the 6-digit code from your authenticator app:</label>
                                    <input
                                        type="text"
                                        id="verification-code"
                                        placeholder="000000"
                                        value={verificationCode}
                                        onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                        maxLength="6"
                                        className="verification-code-input"
                                        autoFocus
                                    />
                                    <p className="help-text">
                                        Open your authenticator app to get the current code
                                    </p>
                                </div>
                                <div className="button-group">
                                    <button
                                        className="confirm-disable-btn"
                                        onClick={handleDisable2FA}
                                        disabled={loading || verificationCode.length !== 6}
                                    >
                                        {loading ? 'Disabling...' : 'Yes, Disable 2FA'}
                                    </button>
                                    <button
                                        className="cancel-btn"
                                        onClick={handleCancelDisable}
                                        disabled={loading}
                                    >
                                        Cancel
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>
                )}

                <div className="help-section">
                    <h4>Need Help?</h4>
                    <p>
                        <strong>Recommended Authenticator Apps:</strong> Google Authenticator, Microsoft Authenticator, Authy
                    </p>
                    <p>
                        Lost access to your authenticator? Use one of your backup codes to log in, then disable and re-enable 2FA.
                    </p>
                </div>
            </div>
        </div>
    );
};

export default TwoFactorManagement;
