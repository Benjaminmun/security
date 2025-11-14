
import axios from 'axios';

// Base URL for the API
const BASE_URL = 'http://localhost:8081';

export const checkAccountExists = async (username, ic) => {
    try {
        
        const response = await axios.post(`${BASE_URL}/check-account-exist`, { username, ic, userType: "users" });
        return response.data;

    } catch (error) {
        throw new Error('Error checking account existence');
    }
};

export const registerUser = async (username, ic, password) => {
    try {
        const response = await axios.post(`${BASE_URL}/register`, { username, ic, password, userType: "users" });
        return response.data;
    } catch (error) {
        throw new Error('Registration failed');
    }
};
