import React from 'react';
import './CompletePage.css';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const CompletePage = () => {
  const navigate = useNavigate();

  const handleLogout = async () => {
    try {
      const response = await axios.post('http://localhost:8081/logout', {}, { withCredentials: true });
  
      if (response.status === 200) {
        console.log(response.data.message); 
        navigate('/login'); // Redirect to the login page
      } else {
        console.error('Logout failed');
      }
    } catch (error) {
      console.error('Error during logout:', error);
    }
  };

  return (
    <div className="complete-page-wrapper">
      <div className="thank-you-container">
        <div className="icon-container">
          <div className="check-icon">&#10004;</div>
        </div>
        <h1 className="thank-you-heading">Thank you</h1>
        <p className="thank-you-message">
          That’s all we need to start verifying your identity
        </p>
        <button className="back-button" onClick={handleLogout}>
          Back
        </button>
      </div>
    </div>
  );
};

export default CompletePage;