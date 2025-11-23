/**
 * Admin Homepage - OpenStreetMap Implementation
 * 
 * SECURITY MIGRATION: Replaced Google Maps with OpenStreetMap
 * - Using Leaflet with OpenStreetMap tiles
 * - Custom colored markers based on user status
 * - All original functionality preserved
 */

import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import styles from './adminhomepage.module.css';

function AdminHomepage() {
    const navigate = useNavigate();
    const [users, setUsers] = useState([]);

    useEffect(() => {
        const fetchUsers = async () => {
            try {
                const response = await axios.get('http://localhost:8081/users', {withCredentials: true});
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

    // Center on first user or default to KL
    const center = users.length > 0 && users[0].selected_latitude && users[0].selected_longitude
        ? [parseFloat(users[0].selected_latitude), parseFloat(users[0].selected_longitude)]
        : [3.1390, 101.6869];

    /**
     * SECURITY UPDATE: Custom marker icons for OpenStreetMap (replaces Google marker icons)
     * Creates colored circular markers based on user status
     */
    const getMarkerIcon = (status) => {
        const colorMap = {
            green: '#00ff00',
            yellow: '#ffff00',
            red: '#ff0000',
            pending: '#0000ff'
        };
        
        const color = colorMap[status.toLowerCase()] || '#0000ff';
        
        return L.divIcon({
            className: 'custom-marker',
            html: `<div style="
                background-color: ${color};
                width: 30px;
                height: 30px;
                border-radius: 50%;
                border: 3px solid white;
                box-shadow: 0 2px 5px rgba(0,0,0,0.3);
            "></div>`,
            iconSize: [30, 30],
            iconAnchor: [15, 15]
        });
    };

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
                        <Link to="/settings" className={styles.actionButton}>Settings</Link>
                        <Link to="/security-settings" className={styles.actionButton}>Security Settings</Link>
                        <button onClick={logout} className={`${styles.button} ${styles.logoutButton}`}>Logout</button>
                    </div>
                </section>

                <section className={styles.card}>
                    <h2>User Locations (OpenStreetMap)</h2>
                    <MapContainer
                        center={center}
                        zoom={10}
                        style={mapContainerStyle}
                    >
                        <TileLayer
                            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                        />
                        {users.map((user) => {
                            const lat = parseFloat(user.selected_latitude);
                            const lng = parseFloat(user.selected_longitude);
                            
                            if (isNaN(lat) || isNaN(lng)) {
                                console.warn(`Invalid coordinates for user ID ${user.id}`);
                                return null;
                            }

                            return (
                                <Marker
                                    key={user.id}
                                    position={[lat, lng]}
                                    icon={getMarkerIcon(user.status)}
                                >
                                    <Popup>
                                        <div style={{ maxWidth: '200px', fontSize: '14px', color: '#333' }}>
                                            <h3 style={{ fontSize: '16px', margin: '0 0 5px' }}>User ID: {user.id}</h3>
                                            <p><strong>IC:</strong> {user.ic}</p>
                                            <p><strong>Status:</strong> {user.status}</p>
                                            <p><strong>Address:</strong> {user.selected_address}</p>
                                            <p><strong>Lat:</strong> {user.selected_latitude}</p>
                                            <p><strong>Lng:</strong> {user.selected_longitude}</p>
                                            {user.reason && <p><strong>Reason:</strong> {user.reason}</p>}
                                        </div>
                                    </Popup>
                                </Marker>
                            );
                        })}
                    </MapContainer>
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
                                                    loading="lazy"
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
