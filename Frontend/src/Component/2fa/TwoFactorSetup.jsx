import React, { useState } from 'react';
import axios from 'axios';
import './TwoFactorSetup.css';

const TwoFactorSetup = ({ userId, userType, onClose, onSuccess }) => {
    const [step, setStep] = useState(1); // 1: Show QR, 2: Verify Token
    const [qrCode, setQrCode] = useState('');
    const [secret, setSecret] = useState('');
    const [verificationCode, setVerificationCode] = useState('');
    const [backupCodes, setBackupCodes] = useState([]);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    // Step 1: Setup 2FA - Get QR Code
    const handleSetup2FA = async () => {
        setLoading(true);
        setError('');

        try {
            const response = await axios.post(
                'http://localhost:8081/2fa/setup',
                { userId, userType },
                { withCredentials: true }
            );

            setQrCode(response.data.qrCode);
            setSecret(response.data.manualEntryKey);
            setStep(2);
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to setup 2FA');
        } finally {
            setLoading(false);
        }
    };

    // Step 2: Verify Token and Enable 2FA
    const handleVerifyToken = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        try {
            const response = await axios.post(
                'http://localhost:8081/2fa/verify-setup',
                { userId, userType, token: verificationCode },
                { withCredentials: true }
            );

            setBackupCodes(response.data.backupCodes);
            setStep(3);
        } catch (err) {
            setError(err.response?.data?.message || 'Invalid verification code');
        } finally {
            setLoading(false);
        }
    };

    // Step 3: Download/Copy Backup Codes
    const handleDownloadBackupCodes = () => {
        const content = `DBKL Project - Backup Codes\nGenerated: ${new Date().toLocaleString()}\n\n${backupCodes.join('\n')}\n\nKeep these codes safe! Each code can only be used once.`;
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `2FA-backup-codes-${Date.now()}.txt`;
        a.click();
        URL.revokeObjectURL(url);
    };

    const handleCopyBackupCodes = () => {
        navigator.clipboard.writeText(backupCodes.join('\n'));
        alert('Backup codes copied to clipboard!');
    };

    const handleComplete = () => {
        if (onSuccess) onSuccess();
        if (onClose) onClose();
    };

    // Start setup automatically when component mounts
    React.useEffect(() => {
        handleSetup2FA();
    }, []); 

    return (
        <div className="two-factor-setup-overlay">
            <div className="two-factor-setup-modal">
                <div className="modal-header">
                    <h2>Enable Two-Factor Authentication</h2>
                    <button className="close-btn" onClick={onClose}>&times;</button>
                </div>

                <div className="modal-body">
                    {loading && <div className="loading-spinner">Loading...</div>}
                    {error && <div className="error-message">{error}</div>}

                    {/* Step 1 & 2: QR Code and Verification */}
                    {step === 2 && (
                        <div className="setup-step">
                            <h3>Step 1: Scan QR Code</h3>
                            <p>Use an authenticator app like Google Authenticator, Authy, or Microsoft Authenticator to scan this QR code:</p>

                            {qrCode && (
                                <div className="qr-code-container">
                                    <img src={qrCode} alt="2FA QR Code" />
                                </div>
                            )}

                            <div className="manual-entry">
                                <p><strong>Can't scan?</strong> Enter this code manually:</p>
                                <code className="secret-code">{secret}</code>
                            </div>

                            <h3>Step 2: Enter Verification Code</h3>
                            <form onSubmit={handleVerifyToken}>
                                <input
                                    type="text"
                                    placeholder="Enter 6-digit code"
                                    value={verificationCode}
                                    onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                    maxLength="6"
                                    className="verification-input"
                                    required
                                />
                                <button type="submit" className="verify-btn" disabled={loading || verificationCode.length !== 6}>
                                    Verify and Enable 2FA
                                </button>
                            </form>
                        </div>
                    )}

                    {/* Step 3: Backup Codes */}
                    {step === 3 && (
                        <div className="setup-step backup-codes-step">
                            <h3>Save Your Backup Codes</h3>
                            <p className="warning-text">
                                Store these backup codes in a safe place. You can use them to access your account if you lose your authenticator device.
                                Each code can only be used once.
                            </p>

                            <div className="backup-codes-container">
                                {backupCodes.map((code, index) => (
                                    <div key={index} className="backup-code">{code}</div>
                                ))}
                            </div>

                            <div className="backup-actions">
                                <button onClick={handleDownloadBackupCodes} className="download-btn">
                                    Download Codes
                                </button>
                                <button onClick={handleCopyBackupCodes} className="copy-btn">
                                    Copy to Clipboard
                                </button>
                            </div>

                            <button onClick={handleComplete} className="complete-btn">
                                I've Saved My Backup Codes
                            </button>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default TwoFactorSetup;