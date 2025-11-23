ALTER TABLE admin
ADD COLUMN two_fa_secret VARCHAR(255) DEFAULT NULL COMMENT 'Encrypted TOTP secret',
ADD COLUMN two_fa_enabled TINYINT(1) DEFAULT 0 COMMENT '0=disabled, 1=enabled',
ADD COLUMN two_fa_backup_codes TEXT DEFAULT NULL COMMENT 'JSON array of backup codes';

-- Add 2FA columns to users table
ALTER TABLE users
ADD COLUMN two_fa_secret VARCHAR(255) DEFAULT NULL COMMENT 'Encrypted TOTP secret',
ADD COLUMN two_fa_enabled TINYINT(1) DEFAULT 0 COMMENT '0=disabled, 1=enabled',
ADD COLUMN two_fa_backup_codes TEXT DEFAULT NULL COMMENT 'JSON array of backup codes';

-- Create index for better query performance
CREATE INDEX idx_admin_2fa_enabled ON admin(two_fa_enabled);
CREATE INDEX idx_users_2fa_enabled ON users(two_fa_enabled);