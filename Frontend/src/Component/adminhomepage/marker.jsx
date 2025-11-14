/**
 * Marker Component - OpenStreetMap Implementation
 * 
 * SECURITY MIGRATION: Replaced Google Maps Marker with Leaflet Marker
 * - Custom colored markers for different statuses
 * - Compatible with react-leaflet
 * 
 * Note: This component may be deprecated as markers are now created
 * directly in adminhompage.jsx. Kept for backward compatibility.
 */

import React, { useState } from 'react';
import { Marker, Popup } from 'react-leaflet';
import L from 'leaflet';

function MarkerComponent({ user }) {
    /**
     * SECURITY UPDATE: Custom marker icons for OpenStreetMap
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

    const lat = parseFloat(user.selected_latitude);
    const lng = parseFloat(user.selected_longitude);

    if (isNaN(lat) || isNaN(lng)) {
        console.warn(`Invalid coordinates for user ID ${user.id}`);
        return null;
    }

    return (
        <Marker
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
                </div>
            </Popup>
        </Marker>
    );
}

export default MarkerComponent;
