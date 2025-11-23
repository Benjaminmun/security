import React from 'react';
import { createBrowserRouter, RouterProvider, Navigate } from 'react-router-dom';
import Login from './Component/login/login';
import Register from './Component/register/register';
import Homepage from './Component/homepage/homepage';
import Camera from './Component/Camera/Camera';
import AdminHomepage from './Component/adminhomepage/adminhompage';
import ManageUsers from './Component/adminhomepage/manageuser';
import CompletePage from './Component/Camera/CompletePage';
<<<<<<< Updated upstream
=======
import ProtectedRoute from './Component/ProtectedRoute';
import SecuritySettings from './Component/settings/SecuritySettings';
>>>>>>> Stashed changes
import { startActivityWatcher, setIdleWarningCallback } from "./utils/activityWatcher";
import { useEffect, useState } from "react";

const router = createBrowserRouter([
    { 
        path: '/', 
        element: <Navigate to="/login" replace /> // Redirect to /login
    },
    {
        path: '/login',
        element: <div><Login/></div>
    },
    {
        path: '/register',
        element: <div><Register/></div>
    },
    {
        path: '/homepage',
        element: <div><Homepage/></div>
    },
    {
        path: '/camera',
        element: <div><Camera/></div>
    },
    {
        path: '/adminhomepage', 
        element: <div><AdminHomepage/></div>
    },
    {
        path: '/manageuser', 
        element: <div><ManageUsers/></div>
    },
    {
        path: '/CompletePage',
<<<<<<< Updated upstream
        element: <div><CompletePage /></div>
=======
        element: (
            <ProtectedRoute requiredRole="users">
                <div><CompletePage /></div>
            </ProtectedRoute>
        )
    },
    {
        path: '/security-settings',
        element: <div><SecuritySettings /></div>
>>>>>>> Stashed changes
    }
]);

function App() {
    const [idleMessage, setIdleMessage] = useState("");

    useEffect(() => {
        startActivityWatcher();

        setIdleWarningCallback((msg) => {
            setIdleMessage(msg);
        });
    }, []);

    return (
        <div>
            {idleMessage && (
                <div style={{ 
                    background: "orange", 
                    padding: "10px", 
                    color: "white",
                    position: "fixed",
                    top: 0,
                    width: "100%",
                    textAlign: "center",
                    zIndex: 9999
                }}>
                    {idleMessage}
                </div>
            )}

            <RouterProvider router={router} />
        </div>
    );
}


export default App;