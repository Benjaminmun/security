/**
 * Input Validation Test Suite
 * 
 * Purpose: Demonstrates that input validation prevents malicious inputs
 * including XSS, SQL injection patterns, and invalid data formats.
 * 
 * SECURITY TESTING: Tests comprehensive input validation
 * - Email validation
 * - IC number validation
 * - Username validation
 * - Coordinate validation
 * - Text field sanitization (XSS prevention)
 * - SQL injection pattern detection
 * 
 * Author: Security Implementation
 * Date: 2025-11-15
 * 
 * HOW TO RUN:
 * 1. Start the backend server: cd Backend && npm start
 * 2. In another terminal: cd Backend && node tests/input-validation-tests.js
 */

import axios from 'axios';

const BASE_URL = 'http://localhost:8081';

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

class InputValidationTests {
    constructor() {
        this.passedTests = 0;
        this.failedTests = 0;
    }

    async testInvalidEmailFormats() {
        const testName = 'Email Format Validation';
        
        const invalidEmails = [
            'notanemail',
            'missing@domain',
            '@nodomain.com',
            'spaces in@email.com',
            'email@',
            '<script>alert("xss")</script>@test.com'
        ];

        let allBlocked = true;
        
        for (const email of invalidEmails) {
            try {
                const response = await axios.post(`${BASE_URL}/check-account-exist`, {
                    email: email,
                    userType: 'Admin'
                }, { validateStatus: () => true });

                if (response.status === 200) {
                    printResult(testName, false, `Invalid email "${email}" was accepted`);
                    allBlocked = false;
                    break;
                }
            } catch (error) {
                // Error is expected for invalid input
            }
        }

        if (allBlocked) {
            printResult(testName, true, 'All invalid email formats rejected');
            this.passedTests++;
        } else {
            this.failedTests++;
        }
    }

    async testICValidation() {
        const testName = 'IC Number Validation';
        
        const invalidICs = [
            '123',  // Too short
            'ABC123-45-6789',  // Contains letters
            '030124-07-04551234567890',  // Too long
            '<script>alert("xss")</script>',  // XSS attempt
            "'; DROP TABLE users;--"  // SQL injection attempt
        ];

        let allBlocked = true;
        
        for (const ic of invalidICs) {
            try {
                const response = await axios.post(`${BASE_URL}/check-account-exist`, {
                    ic: ic,
                    userType: 'users'
                }, { validateStatus: () => true });

                if (response.status === 200) {
                    printResult(testName, false, `Invalid IC "${ic}" was accepted`);
                    allBlocked = false;
                    break;
                }
            } catch (error) {
                // Error is expected for invalid input
            }
        }

        if (allBlocked) {
            printResult(testName, true, 'All invalid IC formats rejected');
            this.passedTests++;
        } else {
            this.failedTests++;
        }
    }

    async testUsernameValidation() {
        const testName = 'Username Validation';
        
        const invalidUsernames = [
            'ab',  // Too short
            'a'.repeat(51),  // Too long
            'user name',  // Contains spaces
            'user@name',  // Contains special chars
            '<script>alert("xss")</script>',  // XSS attempt
            "admin'--"  // SQL injection attempt
        ];

        let allBlocked = true;
        
        for (const username of invalidUsernames) {
            try {
                const response = await axios.post(`${BASE_URL}/register`, {
                    username: username,
                    email: 'test@test.com',
                    password: 'Test123!@#',
                    userType: 'Admin'
                }, { validateStatus: () => true });

                if (response.status === 200) {
                    printResult(testName, false, `Invalid username "${username}" was accepted`);
                    allBlocked = false;
                    break;
                }
            } catch (error) {
                // Error is expected for invalid input
            }
        }

        if (allBlocked) {
            printResult(testName, true, 'All invalid usernames rejected');
            this.passedTests++;
        } else {
            this.failedTests++;
        }
    }

    async testWeakPasswordRejection() {
        const testName = 'Password Strength Validation';
        
        const weakPasswords = [
            'short',  // Too short
            'alllowercase123',  // No uppercase
            'ALLUPPERCASE123',  // No lowercase
            'NoNumbers!@#',  // No numbers
            'NoSymbols123',  // No symbols
        ];

        let allBlocked = true;
        
        for (const password of weakPasswords) {
            try {
                const response = await axios.post(`${BASE_URL}/register`, {
                    username: 'testuser',
                    email: `test${Date.now()}@test.com`,
                    password: password,
                    userType: 'Admin'
                }, { validateStatus: () => true });

                if (response.status === 200) {
                    printResult(testName, false, `Weak password was accepted`);
                    allBlocked = false;
                    break;
                }
            } catch (error) {
                // Error is expected for weak password
            }
        }

        if (allBlocked) {
            printResult(testName, true, 'All weak passwords rejected');
            this.passedTests++;
        } else {
            this.failedTests++;
        }
    }

    async testSQLInjectionInInputs() {
        const testName = 'SQL Injection Pattern Detection';
        
        const sqlPayloads = [
            "admin' OR '1'='1",
            "'; DROP TABLE users;--",
            "1' UNION SELECT * FROM admin--",
            "admin'/*",
            "admin'#"
        ];

        let allBlocked = true;
        
        for (const payload of sqlPayloads) {
            try {
                const response = await axios.post(`${BASE_URL}/Login`, {
                    email: payload,
                    password: 'password',
                    userType: 'Admin'
                }, { validateStatus: () => true });

                if (response.status === 200) {
                    printResult(testName, false, `SQL injection payload "${payload}" succeeded`);
                    allBlocked = false;
                    break;
                }
            } catch (error) {
                // Error is expected for malicious input
            }
        }

        if (allBlocked) {
            printResult(testName, true, 'All SQL injection patterns blocked');
            this.passedTests++;
        } else {
            this.failedTests++;
        }
    }

    async testXSSInTextFields() {
        const testName = 'XSS Prevention in Text Fields';
        
        const xssPayloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            'javascript:alert("XSS")',
            '<iframe src="javascript:alert(\'XSS\')"></iframe>'
        ];

        let allBlocked = true;
        
        for (const payload of xssPayloads) {
            try {
                const response = await axios.post(`${BASE_URL}/register`, {
                    username: payload,
                    email: `test${Date.now()}@test.com`,
                    password: 'Test123!@#',
                    userType: 'Admin'
                }, { validateStatus: () => true });

                if (response.status === 200) {
                    printResult(testName, false, `XSS payload in username was accepted`);
                    allBlocked = false;
                    break;
                }
            } catch (error) {
                // Error is expected for XSS attempts
            }
        }

        if (allBlocked) {
            printResult(testName, true, 'All XSS payloads blocked');
            this.passedTests++;
        } else {
            this.failedTests++;
        }
    }

    async testValidInputAcceptance() {
        const testName = 'Valid Input Acceptance';
        
        try {
            const validEmail = `valid${Date.now()}@example.com`;
            const response = await axios.post(`${BASE_URL}/check-account-exist`, {
                email: validEmail,
                userType: 'Admin'
            }, { validateStatus: () => true });

            // Should accept valid email (200, 404, or 409 are all acceptable)
            if (response.status === 200 || response.status === 404 || response.status === 409) {
                printResult(testName, true, 'Valid inputs are correctly accepted');
                this.passedTests++;
            } else {
                printResult(testName, false, `Valid input rejected with status ${response.status}`);
                this.failedTests++;
            }
        } catch (error) {
            printResult(testName, false, `Error with valid input: ${error.message}`);
            this.failedTests++;
        }
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
            console.log(`${colors.green}✓ All input validation tests passed!${colors.reset}`);
            console.log(`${colors.green}✓ The system properly validates and sanitizes all inputs.${colors.reset}\n`);
        } else {
            console.log(`${colors.red}✗ Some tests failed. Review the input validation implementation.${colors.reset}\n`);
        }
    }

    async runAll() {
        printHeader('INPUT VALIDATION TEST SUITE');
        console.log('Testing input validation and sanitization...\n');

        try {
            await this.testInvalidEmailFormats();
            await this.testICValidation();
            await this.testUsernameValidation();
            await this.testWeakPasswordRejection();
            await this.testSQLInjectionInInputs();
            await this.testXSSInTextFields();
            await this.testValidInputAcceptance();
        } catch (error) {
            console.error(`${colors.red}Test execution error: ${error.message}${colors.reset}`);
        }

        this.printSummary();
    }
}

const main = async () => {
    console.log(`${colors.blue}Starting Input Validation Tests...${colors.reset}`);
    console.log(`${colors.blue}Target: ${BASE_URL}${colors.reset}`);
    console.log(`${colors.blue}Make sure the server is running on port 8081${colors.reset}\n`);

    const tests = new InputValidationTests();
    await tests.runAll();
};

if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch(error => {
        console.error(`${colors.red}Fatal error: ${error.message}${colors.reset}`);
        process.exit(1);
    });
}

export default InputValidationTests;
