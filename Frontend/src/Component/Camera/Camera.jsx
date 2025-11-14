import React, { useState, useRef, useEffect } from 'react';
import { GoogleMap, LoadScript, Autocomplete, Marker } from '@react-google-maps/api';
import './camera.css';
import {Link, useNavigate} from 'react-router-dom';


const Camera = () => {
    const [imageDataUrl, setImageDataUrl] = useState('');
    const [comparisonResult, setComparisonResult] = useState('');
    const [location, setLocation] = useState({ latitude: null, longitude: null });
    const [selectedLocation, setSelectedLocation] = useState({ latitude: null, longitude: null });
    const [selectedAddress, setSelectedAddress] = useState(null);
    const [autocomplete, setAutocomplete] = useState(null);
    const [warningMessage, setWarningMessage] = useState('');
    const [statusColor, setStatusColor] = useState('');
    const [isLoading, setIsLoading] = useState(false);
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

    const captureLocation = async () => {
        try {
            const response = await fetch('https://www.googleapis.com/geolocation/v1/geolocate?key=AIzaSyBuPum0hFde7ZQLB6arVJ0F2EQJfmPv0Rs', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ considerIp: true }),
            });
    
            if (response.ok) {
                const locationData = await response.json();
                const { lat, lng } = locationData.location;
                
                setLocation({
                    latitude: lat,
                    longitude: lng,
                });
    
                console.log('Location from Google API:', locationData.location);
                return { latitude: lat, longitude: lng };
            } else {
                console.error('Failed to fetch location from Google API');
                return null;
            }
        } catch (error) {
            console.error('Error with Google Geolocation API:', error);
            return null;
        }
    };
    
    const saveLocationData = async (capturedLocation, selectedLocation, selectedAddress) => {
        if (!capturedLocation || capturedLocation.latitude === null || capturedLocation.longitude === null) {
            console.error('Captured location is null. Please ensure location is captured before saving.');
            return;
        }
    
        try {
            const response = await fetch('http://localhost:8081/saveLocation', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
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
    
        setWarningMessage(''); // Clear any existing warning messages
    
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
        console.log('Captured Image Data URL:', dataUrl);
    
        // Capture and save location only
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
            console.log('Captured Image Base64 Length:', base64Image.length);
    
            const response = await fetch('http://localhost:8081/compareFaces', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ capturedImage: base64Image }),
            });
    
            const result = await response.json();
            console.log('Comparison API full result:', result);
    
            const matchResultMessage = result.message.trim();
            console.log('Comparison result message:', matchResultMessage);
    
            setComparisonResult(matchResultMessage);
    
            // Determine if faces match
            const faceMatch = matchResultMessage === 'Faces match';
            console.log("Face Match:", faceMatch); // Log faceMatch result
    
            // Determine if locations match
            const locationMatch = isLocationMatch(location, selectedLocation);
            console.log("Location Match:", locationMatch); // Log locationMatch result
            
            // Determine status based on matches
            const status = determineStatus(locationMatch, faceMatch);
            console.log("Determined Status:", status);

            // Save status to the database
            await saveStatusInDatabase(status);

            // Determine reason based on matches
            const reason = determineReason(locationMatch, faceMatch);
            console.log("Determined Reason:", reason);

            // Save reason to the database
            await saveReasonInDatabase(reason);

            // Update UI status color
            if (status === 'GREEN') setStatusColor('green');
            else if (status === 'YELLOW') setStatusColor('yellow');
            else setStatusColor('red');

            // Navigate to CompletePage
            navigate('/completepage');
        } catch (error) {
            console.error('Error comparing faces:', error);
            setComparisonResult('Error comparing faces.');
        }
    };
    
    const fetchAddress = async (lat, lng) => {
        try {
            const response = await fetch(`https://maps.googleapis.com/maps/api/geocode/json?latlng=${lat},${lng}&key=AIzaSyBuPum0hFde7ZQLB6arVJ0F2EQJfmPv0Rs`);
            const data = await response.json();
            console.log("Geocoding API response:", data);
    
            if (data.results && data.results[0]) {
                const address = data.results[0].formatted_address;
                setSelectedAddress(address);
            } else {
                setSelectedAddress('Address not found');
            }
        } catch (error) {
            console.error('Error fetching address:', error);
            setSelectedAddress('Error fetching address');
        }
    };
    

    const isLocationMatch = (location1, location2, margin = 0.01) => {
        return (
            Math.abs(location1.latitude - location2.latitude) <= margin &&
            Math.abs(location1.longitude - location2.longitude) <= margin
        );
    };


    const determineStatus = (locationMatch, faceMatch) => {
        if (locationMatch && faceMatch) {
            return 'GREEN';
        } else if (locationMatch) {
            return 'YELLOW';
        } else if (faceMatch) {
            return 'YELLOW';
        } else {
            return 'RED';
        }
    };
    
    const saveStatusInDatabase = async (status) => {
        try {
            const response = await fetch('http://localhost:8081/saveStatus', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',  // Ensure the token is included in the request
                body: JSON.stringify({ status }),
            });
    
            const result = await response.json();
            console.log(result.message);
        } catch (error) {
            console.error('Error saving status:', error);
        }
    };
    

    const determineReason = (locationMatch, faceMatch) => {
        if (locationMatch && faceMatch) {
            return 'Both location and face match';
        } else if (locationMatch) {
            return 'Faces do not match';
        } else if (faceMatch) {
            return 'Locations do not match';
        } else {
            return 'Both location and face do not match';
        }
    };
    
    const saveReasonInDatabase = async (reason) => {
        try {
            const response = await fetch('http://localhost:8081/saveReason', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',  // Ensure the token is included in the request
                body: JSON.stringify({ reason }),
            });
    
            const result = await response.json();
            console.log(result.message);
        } catch (error) {
            console.error('Error saving reason:', error);
        }
    };














    const onLoad = (autocompleteInstance) => {
        setAutocomplete(autocompleteInstance);
    };

    const onPlaceChanged = () => {
        if (autocomplete) {
            const place = autocomplete.getPlace();
            if (place.geometry) {
                const lat = place.geometry.location.lat();
                const lng = place.geometry.location.lng();
                setSelectedLocation({ latitude: lat, longitude: lng });
                fetchAddress(lat, lng);
    
                saveLocationData();
            }
        }
    };
    

    const handleMapClick = (event) => {
        const lat = event.latLng.lat();
        const lng = event.latLng.lng();
        setSelectedLocation({ latitude: lat, longitude: lng });
        fetchAddress(lat, lng); // Fetch address for the selected location
        setWarningMessage(''); // Clear any existing warning message
    };


    return (
        <div className="camera-container">
            
            <h2>Capture Image from Camera</h2>
    
            <div className="content-wrapper">
                {/* Camera and Capture Button */}
                <div className="camera-section">
                    <video ref={videoRef} autoPlay className="camera-video" />
                    <div class="button-container">

                    <button onClick={captureImage} className="camera-btn">Capture Image and Save Location</button>

                    {warningMessage && (
                    <div className="warning-message" style={{ textAlign: 'center', marginTop: '20px', color: 'red' }}>
                        {warningMessage}
                    </div>
                )}
    
                    <canvas ref={canvasRef} style={{ display: 'none' }} />

                    </div>

                </div>
    
                {/* Google Maps with Search and Click Selection */}
                <div className="map-section">
                    <LoadScript googleMapsApiKey="AIzaSyBuPum0hFde7ZQLB6arVJ0F2EQJfmPv0Rs" libraries={['places']}>
                        <GoogleMap
                            center={selectedLocation.latitude && selectedLocation.longitude
                                ? { lat: selectedLocation.latitude, lng: selectedLocation.longitude }
                                : { lat: 0, lng: 0 }}
                            zoom={selectedLocation.latitude ? 15 : 2}
                            mapContainerStyle={{ width: '100%', height: '400px', position: 'relative' }}
                            onClick={handleMapClick}
                        >
                            <div style={{ position: 'absolute', top: '10px', left: '10px', zIndex: '10', width: '80%' }}>
                                <Autocomplete onLoad={onLoad} onPlaceChanged={onPlaceChanged}>
                                    <input
                                        type="text"
                                        placeholder="Search location"
                                        className="map-search-input"
                                        style={{ width: '100%', padding: '8px', borderRadius: '4px' }}
                                    />
                                </Autocomplete>
                            </div>
                            
                            {selectedLocation.latitude && selectedLocation.longitude && (
                                <Marker position={{ lat: selectedLocation.latitude, lng: selectedLocation.longitude }} />
                            )}
                        </GoogleMap>
                    </LoadScript>
                    {/* Display selected location coordinates */}
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

    
            {/* Display captured image and location info */}
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
                        <button
                            onClick={handleCompareFaces}
                            className="camera-btn"
                            disabled={isLoading}
                        >
                            {isLoading ? 'Loading...' : 'Confirm'}
                        </button>
                    </div>
                </div>
            )}
    
            {/* Comparison Result
            {comparisonResult && (
                <div className="comparison-result">
                    <h3>Comparison Result:</h3>
                    <p>{comparisonResult}</p>
                </div>
            )} */}

            {/* Status Indicator
            <div className="status-display">
                <h3>Status:</h3>
                <div className={`status-indicator ${statusColor}`}>
                    <p>{statusColor.toUpperCase()}</p>
                    </div>
            </div> */}

            {/* <div style={{background: '#007bff', borderRadius: '10px',
                 width: '170px', padding:'10px', position: 'fixed', bottom: '0', right:'0'
                 , margin: '0 50px 30px 0px', cursor: 'pointer' }}>
                <Link to="/homepage"><span style={{fontWeight: '600', color: '#fff'}}>Home</span></Link>
            </div> */}

            {isLoading && <p>Loading...</p>}

        </div>
    );
};

export default Camera;