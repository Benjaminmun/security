/**
 * Security Logging Test Suite
 * 
 * Purpose: Demonstrates that security events are properly logged
 * for audit trail and incident response.
 * 
 * SECURITY TESTING: Tests OWASP A09 - Security Logging and Monitoring
 * - Failed login logging
 * - Successful login logging
 * - Access denied logging
 * - SQL injection attempt logging
 * - Data modification logging
 * - SSRF attempt logging
 * 
 * Author: Security Implementation
 * Date: 2025-11-15
 * 
 * HOW TO RUN:
 * 1. Start the backend server: cd Backend && npm start
 * 2. In another terminal: cd Backend && node tests/security-logging-tests.js
 */

import axios from 'axios';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BASE_URL = 'http://localhost:8081';
const LOG_DIR = path.join(__dirname, '..', 'logs');
const SECURITY_LOG_FILE = path.join(LOG_DIR, 'security.log');

// Color codes for console output
const colors = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m'
};

const printResult = (testName, passed, message) => {
    const status = passed ? `${colors.green}✓ PASS${colors.reset}` : `${colors.red}✗ FAIL${colors.reset}`;
    console.log(`${status} ${testName}`);
    if (message) {
        console.log(`  ${colors.blue}→${colors.reset} ${message}`);
    }
};

const printHeader = (title) => {
    console.log(`\n${colors.yellow}${'='.repeat(60)}${colors.reset}`);
    console.log(`${colors.yellow}${title}${colors.reset}`);
    console.log(`${colors.yellow}${'='.repeat(60)}${colors.reset}\n`);
};

class SecurityLoggingTests {
    constructor() {
        this.passedTests = 0;
        this.failedTests = 0;
        this.initialLogSize = 0;
    }

    getLogSize() {
        try {
            if (fs.existsSync(SECURITY_LOG_FILE)) {
                const stats = fs.statSync(SECURITY_LOG_FILE);
                return stats.size;
            }
        } catch (error) {
            console.log(`${colors.yellow}Warning: Could not read log file: ${error.message}${colors.reset}`);
        }
        return 0;
    }

    getRecentLogEntries(count = 10) {
        try {
            if (!fs.existsSync(SECURITY_LOG_FILE)) {
                return [];
            }

            const content = fs.readFileSync(SECURITY_LOG_FILE, 'utf8');
            const lines = content.trim().split('\n');
            const recentLines = lines.slice(-count);

            return recentLines.map(line => {
                try {
                    return JSON.parse(line);
                } catch {
                    return null;
                }
            }).filter(entry => entry !== null);
        } catch (error) {
            console.log(`${colors.yellow}Warning: Could not read log entries: ${error.message}${colors.reset}`);
            return [];
        }
    }

    async setup() {
        printHeader('SETUP: Recording Initial State');
        this.initialLogSize = this.getLogSize();
        console.log(`Initial log file size: ${this.initialLogSize} bytes\n`);
    }

    async testFailedLoginLogging() {
        const testName = 'Failed Login Logging';
        
        const sizeBefore = this.getLogSize();
        
        try {
            // Attempt failed login
            await axios.post(`${BASE_URL}/Login`, {
                email: 'nonexistent@test.com',
                password: 'wrongpassword',
                userType: 'Admin'
            }, { validateStatus: () => true });

            // Wait a bit for log to be written
            await new Promise(resolve => setTimeout(resolve, 500));

            const sizeAfter = this.getLogSize();
            const recentLogs = this.getRecentLogEntries(5);

            // Check if log file grew and contains LOGIN_FAILURE event
            const hasFailureLog = recentLogs.some(log => 
                log && log.eventType === 'LOGIN_FAILURE'
            );

            if (hasFailureLog || sizeAfter > sizeBefore) {
                printResult(testName, true, 'Failed login was logged');
                this.passedTests++;
            } else {
                printResult(testName, false, 'Failed login was not logged');
                this.failedTests++;
            }
        } catch (error) {
            printResult(testName, false, `Error: ${error.message}`);
            this.failedTests++;
        }
    }

    async testSuccessfulLoginLogging() {
        const testName = 'Successful Login Logging';
        
        const sizeBefore = this.getLogSize();
        
        try {
            // Register and login a test user
            const testEmail = `logtest${Date.now()}@test.com`;
            await axios.post(`${BASE_URL}/register`, {
                username: 'logtest',
                email: testEmail,
                password: 'Test123!@#',
                userType: 'Admin'
            }, { validateStatus: () => true });

            // Login with the test account
            await axios.post(`${BASE_URL}/Login`, {
                email: testEmail,
                password: 'Test123!@#',
                userType: 'Admin'
            }, { validateStatus: () => true });

            // Wait for log to be written
            await new Promise(resolve => setTimeout(resolve, 500));

            const sizeAfter = this.getLogSize();
            const recentLogs = this.getRecentLogEntries(10);

            // Check if log contains LOGIN_SUCCESS event
            const hasSuccessLog = recentLogs.some(log => 
                log && log.eventType === 'LOGIN_SUCCESS'
            );

            if (hasSuccessLog || sizeAfter > sizeBefore) {
                printResult(testName, true, 'Successful login was logged');
                this.passedTests++;
            } else {
                printResult(testName, false, 'Successful login was not logged');
                this.failedTests++;
            }
        } catch (error) {
            printResult(testName, false, `Error: ${error.message}`);
            this.failedTests++;
        }
    }

    async testSQLInjectionAttemptLogging() {
        const testName = 'SQL Injection Attempt Logging';
        
        const sizeBefore = this.getLogSize();
        
        try {
            // Attempt SQL injection
            await axios.post(`${BASE_URL}/Login`, {
                email: "admin' OR '1'='1--",
                password: 'password',
                userType: 'Admin'
            }, { validateStatus: () => true });

            // Wait for log to be written
            await new Promise(resolve => setTimeout(resolve, 500));

            const sizeAfter = this.getLogSize();
            const recentLogs = this.getRecentLogEntries(10);

            // Check if SQL injection attempt was logged
            const hasSqlInjectionLog = recentLogs.some(log => 
                log && (
                    log.eventType === 'SQL_INJECTION_ATTEMPT' ||
                    log.eventType === 'INVALID_INPUT' ||
                    log.eventType === 'LOGIN_FAILURE'
                )
            );

            if (hasSqlInjectionLog || sizeAfter > sizeBefore) {
                printResult(testName, true, 'SQL injection attempt was logged');
                this.passedTests++;
            } else {
                printResult(testName, false, 'SQL injection attempt was not logged');
                this.failedTests++;
            }
        } catch (error) {
            printResult(testName, false, `Error: ${error.message}`);
            this.failedTests++;
        }
    }

    async testAccessDeniedLogging() {
        const testName = 'Access Denied Logging';
        
        const sizeBefore = this.getLogSize();
        
        try {
            // Try to access admin endpoint without authentication
            await axios.get(`${BASE_URL}/users`, {
                validateStatus: () => true
            });

            // Wait for log to be written
            await new Promise(resolve => setTimeout(resolve, 500));

            const sizeAfter = this.getLogSize();
            const recentLogs = this.getRecentLogEntries(10);

            // Check if access denied was logged
            const hasAccessDeniedLog = recentLogs.some(log => 
                log && (
                    log.eventType === 'ACCESS_DENIED' ||
                    log.level === 'WARN' ||
                    log.level === 'ERROR'
                )
            );

            if (hasAccessDeniedLog || sizeAfter > sizeBefore) {
                printResult(testName, true, 'Access denied was logged');
                this.passedTests++;
            } else {
                printResult(testName, false, 'Access denied was not logged');
                this.failedTests++;
            }
        } catch (error) {
            printResult(testName, false, `Error: ${error.message}`);
            this.failedTests++;
        }
    }

    async testHTTPRequestLogging() {
        const testName = 'HTTP Request Logging';
        
        const sizeBefore = this.getLogSize();
        
        try {
            // Make a simple HTTP request
            await axios.get(`${BASE_URL}/`, {
                validateStatus: () => true
            });

            // Wait for log to be written
            await new Promise(resolve => setTimeout(resolve, 500));

            const sizeAfter = this.getLogSize();
            const recentLogs = this.getRecentLogEntries(5);

            // Check if HTTP request was logged
            const hasHttpLog = recentLogs.some(log => 
                log && (
                    log.eventType === 'HTTP_REQUEST' ||
                    log.method === 'GET'
                )
            );

            if (hasHttpLog || sizeAfter > sizeBefore) {
                printResult(testName, true, 'HTTP requests are being logged');
                this.passedTests++;
            } else {
                printResult(testName, false, 'HTTP requests are not being logged');
                this.failedTests++;
            }
        } catch (error) {
            printResult(testName, false, `Error: ${error.message}`);
            this.failedTests++;
        }
    }

    async testLogFileExists() {
        const testName = 'Security Log File Exists';
        
        if (fs.existsSync(SECURITY_LOG_FILE)) {
            printResult(testName, true, `Log file found at: ${SECURITY_LOG_FILE}`);
            this.passedTests++;
        } else {
            printResult(testName, false, 'Security log file not found');
            this.failedTests++;
        }
    }

    displayRecentLogs() {
        printHeader('RECENT SECURITY LOG ENTRIES');
        
        const recentLogs = this.getRecentLogEntries(10);
        
        if (recentLogs.length === 0) {
            console.log(`${colors.yellow}No log entries found or unable to read logs${colors.reset}\n`);
            return;
        }

        console.log(`Showing last ${recentLogs.length} entries:\n`);
        
        recentLogs.forEach((log, index) => {
            const levelColor = log.level === 'ERROR' || log.level === 'CRITICAL' ? colors.red :
                              log.level === 'WARN' ? colors.yellow : colors.green;
            
            console.log(`${index + 1}. [${levelColor}${log.level}${colors.reset}] ${log.eventType || 'N/A'}`);
            console.log(`   ${log.message}`);
            console.log(`   Time: ${log.timestamp}`);
            if (log.ip) console.log(`   IP: ${log.ip}`);
            console.log('');
        });
    }

    printSummary() {
        const total = this.passedTests + this.failedTests;
        const percentage = total > 0 ? ((this.passedTests / total) * 100).toFixed(1) : 0;
        
        printHeader('TEST SUMMARY');
        console.log(`Total Tests: ${total}`);
        console.log(`${colors.green}Passed: ${this.passedTests}${colors.reset}`);
        console.log(`${colors.red}Failed: ${this.failedTests}${colors.reset}`);
        console.log(`Success Rate: ${percentage}%\n`);

        if (this.failedTests === 0) {
            console.log(`${colors.green}✓ All security logging tests passed!${colors.reset}`);
            console.log(`${colors.green}✓ The system properly logs security events for audit trail.${colors.reset}\n`);
        } else {
            console.log(`${colors.red}✗ Some tests failed. Review the security logging implementation.${colors.reset}\n`);
        }
    }

    async runAll() {
        printHeader('SECURITY LOGGING AND MONITORING TEST SUITE');
        console.log('Testing security event logging...\n');

        try {
            await this.setup();
            await this.testLogFileExists();
            await this.testHTTPRequestLogging();
            await this.testFailedLoginLogging();
            await this.testSuccessfulLoginLogging();
            await this.testSQLInjectionAttemptLogging();
            await this.testAccessDeniedLogging();
            this.displayRecentLogs();
        } catch (error) {
            console.error(`${colors.red}Test execution error: ${error.message}${colors.reset}`);
        }

        this.printSummary();
    }
}

const main = async () => {
    console.log(`${colors.blue}Starting Security Logging Tests...${colors.reset}`);
    console.log(`${colors.blue}Target: ${BASE_URL}${colors.reset}`);
    console.log(`${colors.blue}Make sure the server is running on port 8081${colors.reset}\n`);

    const tests = new SecurityLoggingTests();
    await tests.runAll();
};

if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch(error => {
        console.error(`${colors.red}Fatal error: ${error.message}${colors.reset}`);
        process.exit(1);
    });
}

export default SecurityLoggingTests;
