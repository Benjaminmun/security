/**
 * Comprehensive Security Test Runner
 * 
 * Purpose: Runs all security test suites and generates a comprehensive report
 * demonstrating that all security measures are functioning correctly.
 * 
 * Test Coverage:
 * 1. SQL Injection Protection
 * 2. Broken Access Control Prevention
 * 3. Input Validation
 * 4. Security Logging and Monitoring
 * 5. SSRF Protection
 * 
 * Author: Security Implementation
 * Date: 2025-11-15
 * 
 * HOW TO RUN:
 * 1. Start the backend server: cd Backend && npm start
 * 2. In another terminal: cd Backend && node tests/run-all-security-tests.js
 */

import SqlInjectionTests from './sql-injection-tests.js';
import AccessControlTests from './access-control-tests.js';
import InputValidationTests from './input-validation-tests.js';
import SecurityLoggingTests from './security-logging-tests.js';
import SSRFProtectionTests from './ssrf-protection-tests.js';

// Color codes for console output
const colors = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m',
    magenta: '\x1b[35m'
};

const printHeader = (title) => {
    console.log(`\n${colors.cyan}${'═'.repeat(70)}${colors.reset}`);
    console.log(`${colors.cyan}${title.padStart((70 + title.length) / 2).padEnd(70)}${colors.reset}`);
    console.log(`${colors.cyan}${'═'.repeat(70)}${colors.reset}\n`);
};

const printSection = (title) => {
    console.log(`\n${colors.magenta}${'─'.repeat(70)}${colors.reset}`);
    console.log(`${colors.magenta}${title}${colors.reset}`);
    console.log(`${colors.magenta}${'─'.repeat(70)}${colors.reset}\n`);
};

class ComprehensiveSecurityTests {
    constructor() {
        this.testSuites = [];
        this.overallResults = {
            totalPassed: 0,
            totalFailed: 0,
            suiteResults: []
        };
    }

    async runAllTests() {
        printHeader('COMPREHENSIVE SECURITY TEST SUITE');
        console.log(`${colors.blue}Testing all OWASP Top 10 security implementations...${colors.reset}`);
        console.log(`${colors.blue}Target: http://localhost:8081${colors.reset}`);
        console.log(`${colors.blue}Date: ${new Date().toISOString()}${colors.reset}\n`);

        // Test Suite 1: SQL Injection Protection
        printSection('1. SQL INJECTION PROTECTION (OWASP - Injection)');
        const sqlTests = new SqlInjectionTests();
        await sqlTests.runAll();
        this.overallResults.suiteResults.push({
            name: 'SQL Injection Protection',
            passed: sqlTests.passedTests,
            failed: sqlTests.failedTests
        });
        this.overallResults.totalPassed += sqlTests.passedTests;
        this.overallResults.totalFailed += sqlTests.failedTests;

        // Test Suite 2: Broken Access Control Prevention
        printSection('2. BROKEN ACCESS CONTROL PREVENTION (OWASP A01)');
        const accessTests = new AccessControlTests();
        await accessTests.runAll();
        this.overallResults.suiteResults.push({
            name: 'Broken Access Control Prevention',
            passed: accessTests.passedTests,
            failed: accessTests.failedTests
        });
        this.overallResults.totalPassed += accessTests.passedTests;
        this.overallResults.totalFailed += accessTests.failedTests;

        // Test Suite 3: Input Validation
        printSection('3. INPUT VALIDATION');
        const inputTests = new InputValidationTests();
        await inputTests.runAll();
        this.overallResults.suiteResults.push({
            name: 'Input Validation',
            passed: inputTests.passedTests,
            failed: inputTests.failedTests
        });
        this.overallResults.totalPassed += inputTests.passedTests;
        this.overallResults.totalFailed += inputTests.failedTests;

        // Test Suite 4: Security Logging and Monitoring
        printSection('4. SECURITY LOGGING AND MONITORING (OWASP A09)');
        const loggingTests = new SecurityLoggingTests();
        await loggingTests.runAll();
        this.overallResults.suiteResults.push({
            name: 'Security Logging and Monitoring',
            passed: loggingTests.passedTests,
            failed: loggingTests.failedTests
        });
        this.overallResults.totalPassed += loggingTests.passedTests;
        this.overallResults.totalFailed += loggingTests.failedTests;

        // Test Suite 5: SSRF Protection
        printSection('5. SSRF PROTECTION (OWASP A10)');
        const ssrfTests = new SSRFProtectionTests();
        ssrfTests.runAll();
        this.overallResults.suiteResults.push({
            name: 'SSRF Protection',
            passed: ssrfTests.passedTests,
            failed: ssrfTests.failedTests
        });
        this.overallResults.totalPassed += ssrfTests.passedTests;
        this.overallResults.totalFailed += ssrfTests.failedTests;

        // Print overall summary
        this.printOverallSummary();
    }

    printOverallSummary() {
        printHeader('OVERALL TEST RESULTS');

        console.log(`${colors.cyan}Individual Test Suite Results:${colors.reset}\n`);
        
        this.overallResults.suiteResults.forEach((suite, index) => {
            const total = suite.passed + suite.failed;
            const percentage = total > 0 ? ((suite.passed / total) * 100).toFixed(1) : 0;
            const status = suite.failed === 0 ? 
                `${colors.green}✓ PASS${colors.reset}` : 
                `${colors.red}✗ FAIL${colors.reset}`;
            
            console.log(`${index + 1}. ${suite.name}`);
            console.log(`   ${status} - ${suite.passed}/${total} tests passed (${percentage}%)`);
            console.log('');
        });

        const totalTests = this.overallResults.totalPassed + this.overallResults.totalFailed;
        const overallPercentage = totalTests > 0 ? 
            ((this.overallResults.totalPassed / totalTests) * 100).toFixed(1) : 0;

        console.log(`${colors.cyan}${'─'.repeat(70)}${colors.reset}\n`);
        console.log(`${colors.cyan}Overall Statistics:${colors.reset}`);
        console.log(`Total Test Suites: ${this.overallResults.suiteResults.length}`);
        console.log(`Total Tests Run: ${totalTests}`);
        console.log(`${colors.green}Total Passed: ${this.overallResults.totalPassed}${colors.reset}`);
        console.log(`${colors.red}Total Failed: ${this.overallResults.totalFailed}${colors.reset}`);
        console.log(`Success Rate: ${overallPercentage}%\n`);

        if (this.overallResults.totalFailed === 0) {
            console.log(`${colors.green}╔${'═'.repeat(68)}╗${colors.reset}`);
            console.log(`${colors.green}║${' '.repeat(68)}║${colors.reset}`);
            console.log(`${colors.green}║  ✓ ALL SECURITY TESTS PASSED!${' '.repeat(37)}║${colors.reset}`);
            console.log(`${colors.green}║${' '.repeat(68)}║${colors.reset}`);
            console.log(`${colors.green}║  The system demonstrates robust security implementations:${' '.repeat(12)}║${colors.reset}`);
            console.log(`${colors.green}║${' '.repeat(68)}║${colors.reset}`);
            console.log(`${colors.green}║  ✓ SQL Injection Protection${' '.repeat(40)}║${colors.reset}`);
            console.log(`${colors.green}║  ✓ Broken Access Control Prevention${' '.repeat(32)}║${colors.reset}`);
            console.log(`${colors.green}║  ✓ Input Validation and Sanitization${' '.repeat(31)}║${colors.reset}`);
            console.log(`${colors.green}║  ✓ Security Logging and Monitoring${' '.repeat(33)}║${colors.reset}`);
            console.log(`${colors.green}║  ✓ SSRF Protection${' '.repeat(50)}║${colors.reset}`);
            console.log(`${colors.green}║${' '.repeat(68)}║${colors.reset}`);
            console.log(`${colors.green}╚${'═'.repeat(68)}╝${colors.reset}\n`);
        } else {
            console.log(`${colors.red}╔${'═'.repeat(68)}╗${colors.reset}`);
            console.log(`${colors.red}║  ✗ SOME SECURITY TESTS FAILED${' '.repeat(38)}║${colors.reset}`);
            console.log(`${colors.red}║  Please review the failed tests above for details.${' '.repeat(17)}║${colors.reset}`);
            console.log(`${colors.red}╚${'═'.repeat(68)}╝${colors.reset}\n`);
        }

        console.log(`${colors.blue}Test execution completed at: ${new Date().toISOString()}${colors.reset}\n`);
    }
}

const main = async () => {
    const runner = new ComprehensiveSecurityTests();
    await runner.runAllTests();
};

if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch(error => {
        console.error(`${colors.red}Fatal error: ${error.message}${colors.reset}`);
        process.exit(1);
    });
}

export default ComprehensiveSecurityTests;
