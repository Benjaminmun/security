import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import styles from './manageusers.module.css';

function ManageUsers() {
    const [users, setUsers] = useState([]);
    const [editingUserId, setEditingUserId] = useState(null);
    const [editData, setEditData] = useState({});
    const [search, setSearch] = useState('');
    const [showModal, setShowModal] = useState(false);
    const [userToDelete, setUserToDelete] = useState(null);
    const [message, setMessage] = useState('');
    const [showEditConfirmation, setShowEditConfirmation] = useState(false);
    const [userToSave, setUserToSave] = useState(null);
    const [updateCounter, setUpdateCounter] = useState(0);
    const navigate = useNavigate();

    useEffect(() => {
        const fetchUsers = async () => {
            try {
                const response = await axios.get('http://localhost:8081/users');
                if (response.status === 200) {
                    // Convert user IDs to numbers
                    const usersWithNumericIds = response.data.map(user => ({
                        ...user,
                        id: Number(user.id)
                    }));
                    setUsers(usersWithNumericIds);
                }
            } catch (error) {
                console.error("Error fetching users:", error);
            }
        };
        fetchUsers();
    }, []);
    

    const deleteUser = async () => {
        try {
            await axios.delete(`http://localhost:8081/users/${userToDelete}`);
            setUsers(users.filter(user => user.id !== userToDelete));
            setShowModal(false);
            setUserToDelete(null);
        } catch (error) {
            console.error("Error deleting user:", error);
        }
    };

    const editUser = (userId) => {
        setEditingUserId(Number(userId));
        const user = users.find(user => user.id === Number(userId));
        if (user) {
            setEditData({
                ic: user.ic,
                status: user.status,
                reason: user.reason,
                selected_address: user.selected_address,
                selected_latitude: user.selected_latitude,
                selected_longitude: user.selected_longitude
            });
        }
    };
    

    const confirmSaveUser = (userId) => {
        setUserToSave(Number(userId));
        setShowEditConfirmation(true);
    };
    

    const saveUser = async () => {
        try {
            console.log("Save function called for user ID:", userToSave);
            console.log("Edit data to save:", editData);
    
            const response = await axios.put(`http://localhost:8081/users/${userToSave}`, editData);
    
            if (response.status === 200) {
                const updatedUser = response.data;
    
                setUsers(prevUsers => 
                    prevUsers.map(user => (user.id === userToSave ? updatedUser : user))
                );
    
                setEditingUserId(null); 
                setEditData({});
                setShowEditConfirmation(false);
                setUserToSave(null);
            } else {
                // Handle non-200 responses if necessary
            }
        } catch (error) {
            console.error("Error saving user:", error);
        }
    };
    

    const handleChange = (e) => {
        const { name, value } = e.target;
        if (name in editData) {
            setEditData(prev => ({ ...prev, [name]: value }));
        }
    };

    const goBack = () => {
        navigate('/adminhomepage');
    };

    const handleSearchChange = (e) => {
        setSearch(e.target.value);
    };

    const openDeleteModal = (userId) => {
        setUserToDelete(userId);
        setShowModal(true);
    };

    const filteredUsers = users.filter(user =>
        (user.ic && user.ic.toLowerCase().includes(search.toLowerCase())) ||
        (user.status && user.status.toLowerCase().includes(search.toLowerCase()))
    );
    
    return (
        <div className={styles.container}>
            <header className={styles.header}>
                <h1>Manage Users</h1>
                <button onClick={goBack} className={styles.backButton}>Back</button>
            </header>
            {message && <p className={styles.message}>{message}</p>}
            <input
                type="text"
                className={styles.searchBar}
                placeholder="Search by IC or status..."
                value={search}
                onChange={handleSearchChange}
            />
            <section className={styles.card}>
                <h2>User Database</h2>
                {filteredUsers.length > 0 ? (
                    <div className={styles.userTableContainer}>
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
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredUsers.map(user => (
                                    <tr key={user.id}>
                                        <td>{user.id}</td>
                                        <td>
                                            {editingUserId === user.id ? (
                                                <input 
                                                    type="text" 
                                                    name="ic" 
                                                    value={editData.ic} 
                                                    onChange={handleChange} 
                                                />
                                            ) : (
                                                user.ic
                                            )}
                                        </td>
                                        <td>
                                            {user.images ? (
                                                <img
                                                    src={`data:image/jpeg;base64,${user.images}`}
                                                    alt="User"
                                                    width="180"
                                                    height="180"
                                                    style={{ marginRight: '15px', borderRadius: '18px' }}
                                                />
                                            ) : (
                                                <span>No images</span>
                                            )}
                                        </td>
                                        <td>
                                            {editingUserId === user.id ? (
                                                <>
                                                    <input 
                                                        type="text" 
                                                        name="selected_latitude" 
                                                        value={editData.selected_latitude} 
                                                        onChange={handleChange} 
                                                    />
                                                    <input 
                                                        type="text" 
                                                        name="selected_longitude" 
                                                        value={editData.selected_longitude} 
                                                        onChange={handleChange} 
                                                    />
                                                </>
                                            ) : (
                                                `${user.selected_latitude}, ${user.selected_longitude}`
                                            )}
                                        </td>
                                        
                                        <td>
                                            {editingUserId === user.id ? (
                                                <input 
                                                    type="text" 
                                                    name="selected_address" 
                                                    value={editData.selected_address} 
                                                    onChange={handleChange} 
                                                />
                                            ) : (
                                                user.selected_address
                                            )}
                                        </td>
                                        <td>
                                            {editingUserId === user.id ? (
                                                <input 
                                                    type="text" 
                                                    name="status" 
                                                    value={editData.status} 
                                                    onChange={handleChange} 
                                                />
                                            ) : (
                                                user.status
                                            )}
                                        </td>
                                        <td>
                                            {editingUserId === user.id ? (
                                                <input 
                                                    type="text" 
                                                    name="reason" 
                                                    value={editData.reason} 
                                                    onChange={handleChange} 
                                                />
                                            ) : (
                                                user.reason
                                            )}
                                        </td>
                                        <td className={`${styles.btnContainer}`}>
                                            {editingUserId === user.id ? (
                                                <>
                                                    <button onClick={() => confirmSaveUser(user.id)} className={`${styles.button} ${styles.saveButton}`}>Save</button>
                                                    <button onClick={() => setEditingUserId(null)} className={`${styles.button} ${styles.cancelButton}`}>Cancel</button>
                                                </>
                                            ) : (
                                                <>
                                                    <button onClick={() => editUser(user.id)} className={`${styles.button} ${styles.editButton}`}>Edit</button>
                                                    <button onClick={() => openDeleteModal(user.id)} className={`${styles.button} ${styles.deleteButton}`}>Delete</button>
                                                </>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                ) : <p>No users found.</p>}
            </section>
            {showModal && (
                <div className={styles.modalOverlay}>
                    <div className={styles.modalContent}>
                        <p>Are you sure you want to delete this user?</p>
                        <div className={styles.modalButtons}>
                            <button onClick={deleteUser} className={`${styles.button} ${styles.deleteButton}`}>Yes</button>
                            <button onClick={() => setShowModal(false)} className={`${styles.button} ${styles.cancelButton}`}>No</button>
                        </div>
                    </div>
                </div>
            )}
            {showEditConfirmation && (
                <div className={styles.modalOverlay}>
                    <div className={styles.modalContent}>
                        <p>Are you sure you want to save changes for this user?</p>
                        <div className={styles.modalButtons}>
                            <button onClick={saveUser} className={`${styles.button} ${styles.saveButton}`}>Yes</button>
                            <button onClick={() => setShowEditConfirmation(false)} className={`${styles.button} ${styles.cancelButton}`}>No</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

export default ManageUsers;