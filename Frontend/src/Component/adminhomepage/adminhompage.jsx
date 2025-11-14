// File: ./Component/adminhomepage/AdminHomepage.js
import React, { useEffect, useState, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { GoogleMap, useLoadScript } from '@react-google-maps/api';
import styles from './adminhomepage.module.css';

function AdminHomepage() {
    const navigate = useNavigate();
    const [users, setUsers] = useState([]);
    const [mapInstance, setMapInstance] = useState(null); // State to store map instance
    const markersRef = useRef([]); // Reference to store marker instances

    const { isLoaded } = useLoadScript({
        googleMapsApiKey: "AIzaSyBuPum0hFde7ZQLB6arVJ0F2EQJfmPv0Rs", // Replace with your actual Google Maps API Key
    });

    useEffect(() => {
        const fetchUsers = async () => {
            try {
                const response = await axios.get('http://localhost:8081/users');
                if (response.status === 200) {
                    setUsers(response.data);
                }
            } catch (error) {
                console.error("Error fetching users:", error);
            }
        };
        fetchUsers();
    }, []);

    const logout = async () => {
        try {
            const response = await axios.post('http://localhost:8081/logout', {}, { withCredentials: true });
            if (response.status === 200) {
                localStorage.removeItem('token');
                navigate('/login');
            }
        } catch (error) {
            console.error("Logout error:", error);
        }
    };

    const mapContainerStyle = {
        width: '100%',
        height: '400px',
        borderRadius: '12px',
        boxShadow: '0 4px 12px rgba(0, 0, 0, 0.1)',
    };

    const center = users.length > 0
        ? {
              lat: parseFloat(users[0].selected_latitude),
              lng: parseFloat(users[0].selected_longitude),
          }
        : { lat: 3.1390, lng: 101.6869 }; // Default center location if no users are available

    const onMapLoad = (map) => {
        setMapInstance(map); // Store map instance
    };

    // Function to determine marker icon based on user status
    const getMarkerIcon = (status) => {
        var status = status.toLowerCase();
        
        switch (status) {
            case 'green':
                return 'http://maps.google.com/mapfiles/ms/icons/green-dot.png';
            case 'yellow':
                return 'http://maps.google.com/mapfiles/ms/icons/yellow-dot.png';
            case 'red':
                return 'http://maps.google.com/mapfiles/ms/icons/red-dot.png';
            default:
                return 'http://maps.google.com/mapfiles/ms/icons/blue-dot.png';
        }
    };

    // useEffect to add markers when mapInstance and users are ready
    useEffect(() => {
        if (mapInstance && users.length > 0) {
            // Clear existing markers to avoid duplicates
            markersRef.current.forEach(marker => marker.setMap(null));
            markersRef.current = [];

            // Add a new marker for each user
            users.forEach((user) => {
                const lat = parseFloat(user.selected_latitude);
                const lng = parseFloat(user.selected_longitude);

                // Validate coordinates
                if (isNaN(lat) || isNaN(lng)) {
                    console.warn(`Invalid coordinates for user ID ${user.id}`);
                    return;
                }

                const position = { lat, lng };

                const marker = new window.google.maps.Marker({
                    position,
                    map: mapInstance,
                    icon: getMarkerIcon(user.status),
                    title: `User ID: ${user.id}`,
                });

                const infoWindow = new window.google.maps.InfoWindow({
                    content: `
                        <div style="max-width: 200px; font-size: 14px; color: #333;">
                            <h3 style="font-size: 16px; margin: 0 0 5px;">User ID: ${user.id}</h3>
                            <p>Status: ${user.status}</p>
                            <p>Address: ${user.selected_address}</p>
                            <p>Lat: ${user.selected_latitude}</p>
                            <p>Lng: ${user.selected_longitude}</p>
                        </div>
                    `,
                });

                marker.addListener('click', () => {
                    infoWindow.open(mapInstance, marker);
                });

                markersRef.current.push(marker);
            });
        }
    }, [mapInstance, users]); // Run when mapInstance or users change

    if (!isLoaded) {
        return <div>Loading...</div>;
    }

    return (
        <div className={styles.container}>
            <header className={styles.header}>
                <h1>Admin Dashboard</h1>
                
            </header>
            <main className={styles.main}>
                <section className={styles.card}>
                    <h2>Admin Actions</h2>
                    <div className={styles.actions}>
                        <Link to="/manageuser" className={styles.actionButton}>Manage Users</Link>
                        <Link to="/view-reports" className={styles.actionButton}>View Reports</Link>
                        <Link to="/security-settings" className={styles.actionButton}>Security Settings</Link>
                        <button onClick={logout} className={`${styles.button} ${styles.logoutButton}`}>Logout</button>
                    </div>
                </section>

                <section className={styles.card}>
                    <h2>User Locations</h2>
                    <GoogleMap
                        mapContainerStyle={mapContainerStyle}
                        center={center}
                        zoom={10}
                        onLoad={onMapLoad}
                    />
                </section>

                <section className={styles.card}>
                    <h2>User Database</h2>
                    {users.length > 0 ? (
                        <div className={styles.tableContainer}>
                            <table className={styles.userTable}>
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>IC</th>
                                        <th>Images</th>
                                        <th>Location</th>
                                        <th>Shop Address</th>
                                        <th>Status</th>
                                        <th>Reason</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {users.map((user) => (
                                        <tr key={user.id}>
                                            <td>{user.id}</td>
                                            <td>{user.ic}</td>
                                            <td>
                                             {user.images ? (
                                                <img
                                                    src={`data:image/jpeg;base64,${user.images}`}
                                                    alt="User"
                                                    className={styles.userImage}
                                                    loading="lazy" // Enables lazy loading
                                                />
                                             ) : (
                                                <span>No images</span>
                                             )}  
                                            </td>
                                            <td>
                                                {user.selected_latitude}, {user.selected_longitude}
                                            </td>
                                            <td>{user.selected_address}</td>
                                            <td>{user.status}</td>
                                            <td>{user.reason}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ) : (
                        <p>No users found.</p>
                    )}
                </section>
            </main>
        </div>
    );
}

export default AdminHomepage;