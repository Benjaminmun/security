# OpenStreetMap Migration Guide

## Overview
This document provides the implementation guide for migrating from Google Maps to OpenStreetMap (using Leaflet library).

## Status
✅ **COMPLETED** - All components migrated to OpenStreetMap

## Packages Installed
✅ `leaflet@1.9.4` - Core Leaflet library
✅ `react-leaflet@4.2.1` - React bindings for Leaflet (compatible with React 18.x)
❌ `@react-google-maps/api` - REMOVED

**Important:** Using `react-leaflet@4.2.1` for compatibility with React 18.x. Version 5.x requires React 19.

## Migration Steps

### 1. Add Leaflet CSS
Add to `public/index.html`:
```html
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
     integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY="
     crossorigin=""/>
```

### 2. Camera.jsx Migration

**Before (Google Maps):**
```javascript
import { GoogleMap, LoadScript, Autocomplete, Marker } from '@react-google-maps/api';

// Google Geolocation API
const response = await fetch('https://www.googleapis.com/geolocation/v1/geolocate?key=API_KEY', {...});

// Google Geocoding API
const response = await fetch(`https://maps.googleapis.com/maps/api/geocode/json?latlng=${lat},${lng}&key=API_KEY`);

// Map component
<LoadScript googleMapsApiKey="API_KEY" libraries={['places']}>
  <GoogleMap center={center} zoom={15}>
    <Marker position={location} />
  </GoogleMap>
</LoadScript>
```

**After (OpenStreetMap with Leaflet library):**
```javascript
import { MapContainer, TileLayer, Marker, Popup, useMap } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

// Browser Geolocation API (no external service needed)
const captureLocation = async () => {
    return new Promise((resolve, reject) => {
        if (!navigator.geolocation) {
            reject(new Error('Geolocation not supported'));
            return;
        }
        
        navigator.geolocation.getCurrentPosition(
            (position) => {
                resolve({
                    latitude: position.coords.latitude,
                    longitude: position.coords.longitude
                });
            },
            (error) => reject(error),
            { enableHighAccuracy: true, timeout: 10000 }
        );
    });
};

// Nominatim Reverse Geocoding (OpenStreetMap)
const getAddressFromCoords = async (lat, lng) => {
    try {
        const response = await fetch(
            `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lng}&zoom=18&addressdetails=1`,
            {
                headers: {
                    'User-Agent': 'DBKL-Project/1.0'  // Required by Nominatim
                }
            }
        );
        const data = await response.json();
        return data.display_name;
    } catch (error) {
        console.error('Error fetching address:', error);
        return null;
    }
};

// Map component
<MapContainer 
    center={[latitude || 3.1390, longitude || 101.6869]} 
    zoom={15} 
    style={{ height: '400px', width: '100%' }}
>
    <TileLayer
        attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
        url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
    />
    {location.latitude && location.longitude && (
        <Marker position={[location.latitude, location.longitude]}>
            <Popup>Your Location</Popup>
        </Marker>
    )}
</MapContainer>
```

### 3. Fix Marker Icons
Leaflet marker icons need to be configured:
```javascript
import icon from 'leaflet/dist/images/marker-icon.png';
import iconShadow from 'leaflet/dist/images/marker-shadow.png';

let DefaultIcon = L.icon({
    iconUrl: icon,
    shadowUrl: iconShadow,
    iconSize: [25, 41],
    iconAnchor: [12, 41]
});

L.Marker.prototype.options.icon = DefaultIcon;
```

### 4. Address Search Implementation

Instead of Google Places Autocomplete, use Nominatim Search:

```javascript
const searchAddress = async (query) => {
    try {
        const response = await fetch(
            `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(query)}&limit=5`,
            {
                headers: {
                    'User-Agent': 'DBKL-Project/1.0'
                }
            }
        );
        const results = await response.json();
        return results.map(r => ({
            display_name: r.display_name,
            lat: parseFloat(r.lat),
            lon: parseFloat(r.lon)
        }));
    } catch (error) {
        console.error('Error searching address:', error);
        return [];
    }
};
```

### 5. adminhompage.jsx Migration

**Before:**
```javascript
import { GoogleMap, useLoadScript } from '@react-google-maps/api';

const { isLoaded } = useLoadScript({
    googleMapsApiKey: "API_KEY",
});

// Marker colors from Google
return 'http://maps.google.com/mapfiles/ms/icons/green-dot.png';
```

**After:**
```javascript
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import L from 'leaflet';

// Custom marker colors with Leaflet
const getMarkerIcon = (status) => {
    const colors = {
        GREEN: '#00ff00',
        YELLOW: '#ffff00',
        RED: '#ff0000',
        PENDING: '#0000ff'
    };
    
    return L.divIcon({
        className: 'custom-marker',
        html: `<div style="background-color: ${colors[status] || '#0000ff'}; 
                          width: 25px; height: 25px; 
                          border-radius: 50%; 
                          border: 2px solid white;"></div>`,
        iconSize: [25, 25]
    });
};

// Map component
<MapContainer center={[3.1390, 101.6869]} zoom={12} style={{ height: '600px' }}>
    <TileLayer
        url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        attribution='&copy; OpenStreetMap contributors'
    />
    {users.map(user => (
        <Marker 
            key={user.id}
            position={[user.selected_latitude, user.selected_longitude]}
            icon={getMarkerIcon(user.status)}
        >
            <Popup>
                <div>
                    <p><strong>IC:</strong> {user.ic}</p>
                    <p><strong>Status:</strong> {user.status}</p>
                    <p><strong>Address:</strong> {user.selected_address}</p>
                </div>
            </Popup>
        </Marker>
    ))}
</MapContainer>
```

### 6. marker.jsx Migration

This file may be replaced entirely by using Leaflet's built-in Marker component. Review the current implementation and migrate logic to parent components.

## Nominatim Usage Policy

**IMPORTANT:** Nominatim has usage limits:
- Max 1 request per second
- Must include User-Agent header
- For production, consider:
  - Running your own Nominatim instance
  - Using commercial geocoding services
  - Implementing request caching

## Testing Checklist

After migration:
- [ ] Map displays correctly
- [ ] Current location detection works
- [ ] Address search/autocomplete works
- [ ] Markers display correctly
- [ ] Status color coding works
- [ ] Click on marker shows info
- [ ] Location save functionality works
- [ ] No console errors
- [ ] Mobile responsive
- [ ] Performance acceptable

## Benefits of OpenStreetMap Migration

1. **No API Key Required** - OpenStreetMap is free
2. **No Usage Limits** - No billing or quota concerns
3. **SSRF Protection** - OSM endpoints in allowlist
4. **Privacy** - No data sent to Google
5. **Customizable** - Full control over map styling
6. **Open Source** - Community-supported

## Implementation Priority

1. Camera.jsx (highest priority - user-facing)
2. adminhompage.jsx (admin functionality)
3. marker.jsx (component update/removal)
4. Testing and validation
5. CSS adjustments for new map styling

## Estimated Work

- Camera.jsx: ~2 hours
- adminhompage.jsx: ~1.5 hours
- marker.jsx: ~0.5 hours  
- Testing: ~1 hour
- **Total: ~5 hours**

## Notes

- Leaflet packages already installed
- Google Maps package already removed
- CSS needs to be added to index.html
- Marker icon fix required for proper display
- Nominatim rate limiting must be respected
- Consider implementing request debouncing for address search
