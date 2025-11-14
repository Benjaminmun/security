import React, { useState } from 'react';
import { Marker, InfoWindow } from '@react-google-maps/api';


function MarkerComponent({ user }) {
    const [isOpen, setIsOpen] = useState(false);

    // Function to determine marker color based on user status
    const getMarkerColor = (status) => {
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

    return (
        <Marker
            position={{
                lat: parseFloat(user.selected_latitude),
                lng: parseFloat(user.selected_longitude),
            }}
            icon={getMarkerColor(user.status)}
            onClick={() => setIsOpen(true)}
            title={`User ID: ${user.id}`} // Corrected template literal
        >
            {isOpen && (
                <InfoWindow onCloseClick={() => setIsOpen(false)}>
                    <div style={{ maxWidth: '200px', fontSize: '14px', color: '#333' }}>
                        <h3 style={{ fontSize: '16px', margin: '0 0 5px' }}>User ID: {user.id}</h3>
                        <p>Status: {user.status}</p>
                        <p>Address: {user.selected_address}</p>
                        <p>Lat: {user.selected_latitude}</p>
                        <p>Lng: {user.selected_longitude}</p>
                    </div>
                </InfoWindow>
            )}
        </Marker>
    );
}

export default MarkerComponent;