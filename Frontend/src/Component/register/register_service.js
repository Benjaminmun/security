import axios from 'axios';

// Base URL for the API
const BASE_URL = 'http://localhost:8081';

export const checkAccountExists = async (username, ic) => {
    try {
        const response = await axios.post(`${BASE_URL}/check-account-exist`, { 
            username, 
            ic, 
            userType: "users" 
        });
        return response.data;
    } catch (error) {
        // Enhanced error handling for rate limits
        if (error.response) {
            // Server responded with error status
            const status = error.response.status;
            const message = error.response.data?.message || error.response.data?.error;
            
            const enhancedError = new Error(message || 'Request failed');
            enhancedError.status = status;
            throw enhancedError;
        } else if (error.request) {
            // Network error
            const networkError = new Error('Network error. Please check your connection.');
            networkError.status = 0;
            throw networkError;
        } else {
            // Other errors
            throw new Error('Error checking account existence');
        }
    }
};

export const registerUser = async (username, ic, password) => {
    try {
        const response = await axios.post(`${BASE_URL}/register`, { 
            username, 
            ic, 
            password, 
            userType: "users" 
        });
        return response.data;
    } catch (error) {
        // Enhanced error handling for rate limits
        if (error.response) {
            // Server responded with error status
            const status = error.response.status;
            const message = error.response.data?.message || error.response.data?.error;
            
            const enhancedError = new Error(message || 'Registration failed');
            enhancedError.status = status;
            throw enhancedError;
        } else if (error.request) {
            // Network error
            const networkError = new Error('Network error. Please check your connection.');
            networkError.status = 0;
            throw networkError;
        } else {
            // Other errors
            throw new Error('Registration failed');
        }
    }
};