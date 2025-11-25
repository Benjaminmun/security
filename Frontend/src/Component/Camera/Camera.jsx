/**
 * Camera Component - OpenStreetMap Implementation
 * 
 * SECURITY MIGRATION: Replaced Google Maps with OpenStreetMap
 * - Browser geolocation API (replaces Google Geolocation)
 * - Nominatim reverse geocoding (replaces Google Geocoding)
 * - Leaflet library for map rendering (replaces Google Maps)
 */

import React, { useState, useRef, useEffect } from 'react';
import { MapContainer, TileLayer, Marker, Popup, useMapEvents } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import './camera.css';
import {useNavigate} from 'react-router-dom';

// Fix Leaflet marker icons
import icon from 'leaflet/dist/images/marker-icon.png';
import iconShadow from 'leaflet/dist/images/marker-shadow.png';

let DefaultIcon = L.icon({
    iconUrl: icon,
    shadowUrl: iconShadow,
    iconSize: [25, 41],
    iconAnchor: [12, 41]
});

L.Marker.prototype.options.icon = DefaultIcon;

const Camera = () => {
    const [imageDataUrl, setImageDataUrl] = useState('');
    const [comparisonResult, setComparisonResult] = useState('');
    const [location, setLocation] = useState({ latitude: null, longitude: null });
    const [selectedLocation, setSelectedLocation] = useState({ latitude: null, longitude: null });
    const [selectedAddress, setSelectedAddress] = useState(null);
    const [searchQuery, setSearchQuery] = useState('');
    const [searchResults, setSearchResults] = useState([]);
    const [warningMessage, setWarningMessage] = useState('');
    const [statusColor, setStatusColor] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [mapCenter, setMapCenter] = useState([3.1390, 101.6869]); // KL default
    const [mapZoom, setMapZoom] = useState(12);
    const videoRef = useRef(null);
    const canvasRef = useRef(null);
    const navigate = useNavigate();

    useEffect(() => {
        const startCamera = async () => {
            try {
                const stream = await navigator.mediaDevices.getUserMedia({ video: true });
                if (videoRef.current) {
                    videoRef.current.srcObject = stream;
                }
            } catch (err) {
                console.error('Error accessing camera:', err);
            }
        };

        startCamera();

        return () => {
            if (videoRef.current && videoRef.current.srcObject) {
                videoRef.current.srcObject.getTracks().forEach(track => track.stop());
            }
        };
    }, []);

    // SECURITY UPDATE: Browser Geolocation API (replaces Google Geolocation)
    const captureLocation = async () => {
        return new Promise((resolve, reject) => {
            if (!navigator.geolocation) {
                console.error('Geolocation not supported');
                reject(new Error('Geolocation not supported'));
                return;
            }

            navigator.geolocation.getCurrentPosition(
                (position) => {
                    const locationData = {
                        latitude: position.coords.latitude,
                        longitude: position.coords.longitude
                    };
                    setLocation(locationData);
                    console.log('Location from browser:', locationData);
                    resolve(locationData);
                },
                (error) => {
                    console.error('Error getting location:', error);
                    const fallbackLocation = {
                        latitude: mapCenter[0],
                        longitude: mapCenter[1]
                    };
                    setLocation(fallbackLocation);
                    resolve(fallbackLocation);
                },
                { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
            );
        });
    };
    
    const saveLocationData = async (capturedLocation, selectedLocation, selectedAddress) => {
        if (!capturedLocation || capturedLocation.latitude === null) {
            console.error('Captured location is null');
            return;
        }
    
        try {
            const response = await fetch('http://localhost:8081/saveLocation', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({
                    capturedLatitude: capturedLocation.latitude,
                    capturedLongitude: capturedLocation.longitude,
                    selectedLatitude: selectedLocation.latitude,
                    selectedLongitude: selectedLocation.longitude,
                    selectedAddress: selectedAddress,
                }),
            });
    
            if (response.ok) {
                console.log('Location data saved successfully');
            } else {
                console.error('Failed to save location data');
            }
        } catch (error) {
            console.error('Error saving location data:', error);
        }
    };
    
    const captureImage = async () => {
        if (!selectedLocation.latitude || !selectedLocation.longitude) {
            setWarningMessage('Please select a location on the map before capturing the image.');
            return;
        }
    
        setWarningMessage('');
    
        const canvas = canvasRef.current;
        const video = videoRef.current;
    
        if (!canvas || !video) return;
    
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        const context = canvas.getContext('2d');
    
        context.save();
        context.scale(-1, 1);
        context.drawImage(video, -canvas.width, 0, canvas.width, canvas.height);
        context.restore();
    
        const dataUrl = canvas.toDataURL('image/png');
        setImageDataUrl(dataUrl);
        console.log('Captured Image');
    
        const locationData = await captureLocation();
        if (locationData) {
            await saveLocationData(locationData, selectedLocation, selectedAddress);
        }
    };
    
    const handleCompareFaces = async () => {
        setIsLoading(true);
        if (!imageDataUrl) {
            setComparisonResult('No image captured.');
            return;
        }
    
        try {
            const base64Image = imageDataUrl.split(',')[1];
    
            const response = await fetch('http://localhost:8081/compareFaces', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ capturedImage: base64Image }),
            });
    
            const result = await response.json();
            const matchResultMessage = result.message.trim();
            setComparisonResult(matchResultMessage);
    
            const faceMatch = matchResultMessage === 'Faces match';
            const locationMatch = isLocationMatch(location, selectedLocation);
            const status = determineStatus(locationMatch, faceMatch);
            const reason = determineReason(locationMatch, faceMatch);

            await saveStatusInDatabase(status);
            await saveReasonInDatabase(reason);

            if (status === 'GREEN') setStatusColor('green');
            else if (status === 'YELLOW') setStatusColor('yellow');
            else setStatusColor('red');

            navigate('/completepage');
        } catch (error) {
            console.error('Error comparing faces:', error);
            setComparisonResult('Error comparing faces.');
        }
    };
    
    // SECURITY UPDATE: Nominatim reverse geocoding (replaces Google Geocoding)
    const fetchAddress = async (lat, lng) => {
        try {
            const response = await fetch(
                `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lng}&zoom=18&addressdetails=1`,
                { headers: { 'User-Agent': 'DBKL-Security-Project/1.0' } }
            );
            const data = await response.json();
    
            if (data.display_name) {
                setSelectedAddress(data.display_name);
            } else {
                setSelectedAddress('Address not found');
            }
        } catch (error) {
            console.error('Error fetching address:', error);
            setSelectedAddress('Error fetching address');
        }
    };
    
    // SECURITY UPDATE: Nominatim search (replaces Google Places)
    const handleSearch = async (e) => {
        e.preventDefault();
        if (!searchQuery.trim()) return;

        try {
            const response = await fetch(
                `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(searchQuery)}&limit=5`,
                { headers: { 'User-Agent': 'DBKL-Security-Project/1.0' } }
            );
            const results = await response.json();
            setSearchResults(results);
        } catch (error) {
            console.error('Error searching location:', error);
            setSearchResults([]);
        }
    };

    const selectSearchResult = (result) => {
        const lat = parseFloat(result.lat);
        const lng = parseFloat(result.lon);
        setSelectedLocation({ latitude: lat, longitude: lng });
        setMapCenter([lat, lng]);
        setMapZoom(15);
        fetchAddress(lat, lng);
        setSearchResults([]);
        setSearchQuery('');
        setWarningMessage('');
    };

    const isLocationMatch = (location1, location2, margin = 0.01) => {
        return (
            Math.abs(location1.latitude - location2.latitude) <= margin &&
            Math.abs(location1.longitude - location2.longitude) <= margin
        );
    };

    const determineStatus = (locationMatch, faceMatch) => {
        if (locationMatch && faceMatch) return 'GREEN';
        else if (locationMatch || faceMatch) return 'YELLOW';
        else return 'RED';
    };
    
    const saveStatusInDatabase = async (status) => {
        try {
            await fetch('http://localhost:8081/saveStatus', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ status }),
            });
        } catch (error) {
            console.error('Error saving status:', error);
        }
    };
    
    const determineReason = (locationMatch, faceMatch) => {
        if (locationMatch && faceMatch) return 'Both location and face match';
        else if (locationMatch) return 'Faces do not match';
        else if (faceMatch) return 'Locations do not match';
        else return 'Both location and face do not match';
    };
    
    const saveReasonInDatabase = async (reason) => {
        try {
            await fetch('http://localhost:8081/saveReason', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ reason }),
            });
        } catch (error) {
            console.error('Error saving reason:', error);
        }
    };

    // Map click handler component
    function MapClickHandler() {
        useMapEvents({
            click(e) {
                setSelectedLocation({ latitude: e.latlng.lat, longitude: e.latlng.lng });
                fetchAddress(e.latlng.lat, e.latlng.lng);
                setWarningMessage('');
            }
        });
        return null;
    }

    return (
        <div className="camera-container">
            <h2>Capture Image from Camera</h2>
    
            <div className="content-wrapper">
                <div className="camera-section">
                    <video ref={videoRef} autoPlay className="camera-video" />
                    <div className="button-container">
                        <button onClick={captureImage} className="camera-btn">Capture Image and Save Location</button>
                        {warningMessage && (
                            <div className="warning-message" style={{ textAlign: 'center', marginTop: '20px', color: 'red' }}>
                                {warningMessage}
                            </div>
                        )}
                        <canvas ref={canvasRef} style={{ display: 'none' }} />
                    </div>
                </div>
    
                {/* OpenStreetMap Section */}
                <div className="map-section">
                    <div style={{ marginBottom: '10px' }}>
                        <form onSubmit={handleSearch} style={{ display: 'flex', gap: '5px' }}>
                            <input
                                type="text"
                                placeholder="Search location (e.g., Kuala Lumpur)"
                                className="map-search-input"
                                style={{ flex: 1, padding: '8px', borderRadius: '4px', border: '1px solid #ccc' }}
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                            />
                            <button type="submit" style={{ padding: '8px 16px', borderRadius: '4px', border: 'none', background: '#007bff', color: 'white', cursor: 'pointer' }}>
                                Search
                            </button>
                        </form>
                        {searchResults.length > 0 && (
                            <div style={{ background: 'white', border: '1px solid #ccc', borderRadius: '4px', marginTop: '5px', maxHeight: '200px', overflowY: 'auto' }}>
                                {searchResults.map((result, index) => (
                                    <div
                                        key={index}
                                        style={{ padding: '8px', cursor: 'pointer', borderBottom: '1px solid #eee' }}
                                        onClick={() => selectSearchResult(result)}
                                        onMouseEnter={(e) => e.target.style.background = '#f0f0f0'}
                                        onMouseLeave={(e) => e.target.style.background = 'white'}
                                    >
                                        {result.display_name}
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>

                    <MapContainer center={mapCenter} zoom={mapZoom} style={{ width: '100%', height: '400px' }}>
                        <TileLayer
                            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                        />
                        <MapClickHandler />
                        {selectedLocation.latitude && selectedLocation.longitude && (
                            <Marker position={[selectedLocation.latitude, selectedLocation.longitude]}>
                                <Popup>
                                    Selected Location<br />
                                    {selectedAddress || 'Loading...'}
                                </Popup>
                            </Marker>
                        )}
                    </MapContainer>

                    {selectedLocation.latitude && selectedLocation.longitude && (
                        <div className="selected-location-info">
                            <h3>Selected Location:</h3>
                            <p>Latitude: {selectedLocation.latitude}</p>
                            <p>Longitude: {selectedLocation.longitude}</p>
                            <p>Address: {selectedAddress || 'Loading...'}</p>
                        </div>
                    )}
                </div>
            </div>
    
            {imageDataUrl && (
                <div className="captured-image-container">
                    <h3>Captured Image:</h3>
                    <img src={imageDataUrl} alt="Captured" className="captured-image" />
                    
                    {location.latitude && location.longitude && (
                        <div className="location-info">
                            <h3>Location of Image Taken:</h3>
                            <p>Latitude: {location.latitude}</p>
                            <p>Longitude: {location.longitude}</p>
                        </div>
                    )}
    
                    <div className="compare-button-container">
                        <button onClick={handleCompareFaces} className="camera-btn" disabled={isLoading}>
                            {isLoading ? 'Loading...' : 'Confirm'}
                        </button>
                    </div>
                </div>
            )}

            {isLoading && <p>Loading...</p>}
        </div>
    );
};

export default Camera;
