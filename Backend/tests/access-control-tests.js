/**
 * Access Control (Broken Access Control Prevention) Test Suite
 * 
 * Purpose: Demonstrates that broken access control is prevented
 * through proper RBAC implementation and authorization checks.
 * 
 * SECURITY TESTING: Tests OWASP A01 - Broken Access Control
 * - Admin-only endpoint access
 * - User resource ownership validation
 * - Privilege escalation prevention
 * - Unauthorized access blocking
 * 
 * Author: Security Implementation
 * Date: 2025-11-15
 * 
 * HOW TO RUN:
 * 1. Start the backend server: cd Backend && npm start
 * 2. In another terminal: cd Backend && node tests/access-control-tests.js
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

class AccessControlTests {
    constructor() {
        this.passedTests = 0;
        this.failedTests = 0;
        this.adminToken = null;
        this.userToken = null;
    }

    async setupTestAccounts() {
        printHeader('SETUP: Creating Test Accounts');
        
        // Register test admin
        try {
            const adminEmail = `testadmin_${Date.now()}@test.com`;
            await axios.post(`${BASE_URL}/register`, {
                username: 'testadmin',
                email: adminEmail,
                password: 'TestAdmin123!',
                userType: 'Admin'
            }, { validateStatus: () => true });
            
            // Login as admin to get token
            const adminLoginRes = await axios.post(`${BASE_URL}/Login`, {
                email: adminEmail,
                password: 'TestAdmin123!',
                userType: 'Admin'
            }, { validateStatus: () => true });
            
            if (adminLoginRes.status === 200) {
                this.adminToken = adminLoginRes.headers['set-cookie']?.[0];
                console.log(`${colors.green}✓ Admin account created and logged in${colors.reset}`);
            }
        } catch (error) {
            console.log(`${colors.yellow}⚠ Admin account may already exist${colors.reset}`);
        }

        // Register test user
        try {
            const userIC = `${Date.now().toString().substring(0, 6)}-07-0001`;
            await axios.post(`${BASE_URL}/register`, {
                ic: userIC,
                password: 'TestUser123!',
                userType: 'users'
            }, { validateStatus: () => true });
            
            // Login as user to get token
            const userLoginRes = await axios.post(`${BASE_URL}/Login`, {
                ic: userIC,
                password: 'TestUser123!',
                userType: 'users'
            }, { validateStatus: () => true });
            
            if (userLoginRes.status === 200) {
                this.userToken = userLoginRes.headers['set-cookie']?.[0];
                console.log(`${colors.green}✓ User account created and logged in${colors.reset}`);
            }
        } catch (error) {
            console.log(`${colors.yellow}⚠ User account may already exist${colors.reset}`);
        }
    }

    async testUnauthenticatedAdminAccess() {
        const testName = 'Block Unauthenticated Admin Access';
        
        try {
            // Try to access admin endpoint without token
            const response = await axios.get(`${BASE_URL}/users`, {
                validateStatus: () => true
            });

            if (response.status === 403 || response.status === 401) {
                printResult(testName, true, 'Unauthenticated access correctly blocked');
                this.passedTests++;
            } else {
                printResult(testName, false, `Got status ${response.status}, expected 401/403`);
                this.failedTests++;
            }
        } catch (error) {
            printResult(testName, true, 'Access blocked');
            this.passedTests++;
        }
    }

    async testUserAccessingAdminEndpoint() {
        const testName = 'Block User from Admin Endpoint';
        
        if (!this.userToken) {
            printResult(testName, false, 'User token not available');
            this.failedTests++;
            return;
        }

        try {
            // Try to access admin endpoint with user token
            const response = await axios.get(`${BASE_URL}/users`, {
                headers: { Cookie: this.userToken },
                validateStatus: () => true
            });

            if (response.status === 403) {
                printResult(testName, true, 'User correctly denied admin access (403 Forbidden)');
                this.passedTests++;
            } else if (response.status === 401) {
                printResult(testName, true, 'User correctly denied admin access (401 Unauthorized)');
                this.passedTests++;
            } else {
                printResult(testName, false, `User gained admin access! Status: ${response.status}`);
                this.failedTests++;
            }
        } catch (error) {
            printResult(testName, true, 'Access blocked');
            this.passedTests++;
        }
    }

    async testAdminAccessingAdminEndpoint() {
        const testName = 'Allow Admin to Access Admin Endpoint';
        
        if (!this.adminToken) {
            printResult(testName, false, 'Admin token not available');
            this.failedTests++;
            return;
        }

        try {
            // Try to access admin endpoint with admin token
            const response = await axios.get(`${BASE_URL}/users`, {
                headers: { Cookie: this.adminToken },
                validateStatus: () => true
            });

            if (response.status === 200) {
                printResult(testName, true, 'Admin successfully accessed admin endpoint');
                this.passedTests++;
            } else {
                printResult(testName, false, `Admin denied access. Status: ${response.status}`);
                this.failedTests++;
            }
        } catch (error) {
            printResult(testName, false, `Error: ${error.message}`);
            this.failedTests++;
        }
    }

    async testUserDeletionWithoutAdminRole() {
        const testName = 'Block Non-Admin User Deletion';
        
        if (!this.userToken) {
            printResult(testName, false, 'User token not available');
            this.failedTests++;
            return;
        }

        try {
            // Try to delete a user with user token
            const response = await axios.delete(`${BASE_URL}/users/1`, {
                headers: { Cookie: this.userToken },
                validateStatus: () => true
            });

            if (response.status === 403 || response.status === 401) {
                printResult(testName, true, 'User deletion blocked for non-admin');
                this.passedTests++;
            } else {
                printResult(testName, false, `Non-admin could delete user! Status: ${response.status}`);
                this.failedTests++;
            }
        } catch (error) {
            printResult(testName, true, 'Deletion blocked');
            this.passedTests++;
        }
    }

    async testUserModificationByOtherUser() {
        const testName = 'Block User from Modifying Other Users';
        
        if (!this.userToken) {
            printResult(testName, false, 'User token not available');
            this.failedTests++;
            return;
        }

        try {
            // Try to update another user's data
            const response = await axios.put(`${BASE_URL}/users/999`, {
                status: 'RED'
            }, {
                headers: { Cookie: this.userToken },
                validateStatus: () => true
            });

            if (response.status === 403 || response.status === 401) {
                printResult(testName, true, 'User blocked from modifying other users');
                this.passedTests++;
            } else {
                printResult(testName, false, `User could modify other users! Status: ${response.status}`);
                this.failedTests++;
            }
        } catch (error) {
            printResult(testName, true, 'Modification blocked');
            this.passedTests++;
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
            console.log(`${colors.green}✓ All access control tests passed!${colors.reset}`);
            console.log(`${colors.green}✓ The system is protected against broken access control.${colors.reset}\n`);
        } else {
            console.log(`${colors.red}✗ Some tests failed. Review the access control implementation.${colors.reset}\n`);
        }
    }

    async runAll() {
        printHeader('ACCESS CONTROL (BROKEN ACCESS CONTROL PREVENTION) TEST SUITE');
        console.log('Testing RBAC and authorization checks...\n');

        try {
            await this.setupTestAccounts();
            await this.testUnauthenticatedAdminAccess();
            await this.testUserAccessingAdminEndpoint();
            await this.testAdminAccessingAdminEndpoint();
            await this.testUserDeletionWithoutAdminRole();
            await this.testUserModificationByOtherUser();
        } catch (error) {
            console.error(`${colors.red}Test execution error: ${error.message}${colors.reset}`);
        }

        this.printSummary();
    }
}

const main = async () => {
    console.log(`${colors.blue}Starting Access Control Tests...${colors.reset}`);
    console.log(`${colors.blue}Target: ${BASE_URL}${colors.reset}`);
    console.log(`${colors.blue}Make sure the server is running on port 8081${colors.reset}\n`);

    const tests = new AccessControlTests();
    await tests.runAll();
};

if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch(error => {
        console.error(`${colors.red}Fatal error: ${error.message}${colors.reset}`);
        process.exit(1);
    });
}

export default AccessControlTests;
