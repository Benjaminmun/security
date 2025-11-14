import styles from './homepage.module.css';
import { Link, useNavigate} from 'react-router-dom';

import { useRef, useState, useEffect} from 'react';

//icons
import { LiaTimesSolid } from "react-icons/lia";
import { LuFilePlus2 } from "react-icons/lu";
import { BsFileEarmark } from "react-icons/bs";
import axios from 'axios';

function Homepage() {
    const dialogRef = useRef(null);
    const [file, setFile] = useState(null); 
    const [remainingAttempts, setRemainingAttempts] = useState(null); // Track remaining upload attempts
    const [token, setToken] = useState(null);   
    const [isUploaded, setIsUploaded] = useState(false);
    const navigate = useNavigate();

    const openDialog = () => {
        dialogRef.current.showModal();
    };

    const closeDialog = () => {
        dialogRef.current.close();
    };

    const fileExist = (newFileName) => {
        return file && file.name === newFileName.name; // Changed to use file
    };

    const validExtensions = (file) => {
        const allowedExtensions = ['jpeg', 'jpg', 'png'];
        const fileExtension = file.name.split('.').pop().toLowerCase();
        return allowedExtensions.includes(fileExtension);
    };

    const validFileSize = (file, maxSizeMb) => {
        const maxFileSizeInMb = maxSizeMb || 25; // file size maximum 25 MB
        const fileSize = file.size;
        const fileSizeInMb = Math.round(fileSize / 1048576);
        return fileSizeInMb <= maxFileSizeInMb;
    };

    const isValidExtension = (file) => {
        if (!validExtensions(file)) {
            alert(`${file.name} does not have a valid file extension.`);
            return false;
        }
        return true;
    };

    const isValidSize = (file) => {
        if (!validFileSize(file)) {
            alert(`${file.name} has an invalid file size. Maximum file size is 25MB.`);
            return false;
        }
        return true;
    };

    const isNewFile = (file) => {
        if (fileExist(file)) {
            alert(`${file.name} already exists.`);
            return false;
        }
        return true;
    };

    const handleFileInput = (event) => {
        const selectedFile = event.target.files[0];
        if (selectedFile && isNewFile(selectedFile) && isValidExtension(selectedFile) && isValidSize(selectedFile)) {
            setFile(selectedFile); // Update state to a single file
            setIsUploaded(false); // Reset upload status
            console.log("Valid files selected:", selectedFile);
        }
        event.target.value = null; // clear an input
    };

    const handleFileDrop = (event) => {
        event.preventDefault(); // Prevent default behavior
        const droppedFile = event.dataTransfer.files[0];
        if (droppedFile && isNewFile(droppedFile) && isValidExtension(droppedFile) && isValidSize(droppedFile)) {
            setFile(droppedFile); // Update state to a single file
            setIsUploaded(false); // Reset upload status
            console.log("Files dropped:", droppedFile);
        }
        event.target.value = null; // clear an input
    };

    const isImage = (file) => {
        return file && file.type && file.type.split('/')[0] === "image"; // Safeguard against undefined
    };

    const fileSize = (sizeInBytes) => {
        const names = ['bytes', 'Kib', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB'];
        let count = 0, size = parseInt(sizeInBytes, 10) || 0;
        while (size >= 1024 && ++count) {
            size /= 1024;
        }
        return size.toFixed(size < 10 && count > 0 ? 1 : 0) + ' ' + names[count];
    };

    const handleFileDelete = () => {
        setFile(null); // Reset file
        setIsUploaded(false); // Reset upload status
    };

    const fetchUploadAttempts = async () => {
        try {
            const response = await axios.get('http://localhost:8081/getUploadAttempts', {
                withCredentials: true,
            });
    
            if (response.status === 200) {
                setRemainingAttempts(response.data.uploadAttempts);
                setIsUploaded(false)
            } else {
                console.error('Failed to fetch upload attempts');
            }
        } catch (error) {
            console.error('Error fetching upload attempts:', error);
        }
    };
    
    useEffect(() => {
        fetchUploadAttempts(); // Check the upload attempts when the component mounts
    }, []);


    const handleUpload = async () => {
        if (!file) {
            alert('No file selected. Please select an image file to upload.');
            return;
        }

        if(remainingAttempts > 0){
            if(file){
                await uploadFile(file);
            }
        }else{
            window.confirm("No remaining upload attempts.");
            setIsUploaded(true)
        }
    };

    const uploadFile = async (file) => {
        const formData = new FormData(); // Corrected the casing of FormData
        formData.append('file', file); // Append file object to form data
        formData.append('filename', file.name); // Add the filename to form data
    
        try {
            // Step 1: Upload the file
            const response = await axios.post('http://localhost:8081/uploadImage', formData, {
                headers: {
                    'Content-Type': 'multipart/form-data',
                },
                withCredentials: true, // Ensure cookies, including the HTTP-only token, are sent
            });
    
            if (response.status === 200) {
                window.confirm(`${file.name} Upload Successful`);
    
                // Step 2: Update the database to set upload_attempts to false
                // Call your backend to update the upload attempt status
                await axios.post('http://localhost:8081/updateUploadAttempt', {}, {
                    withCredentials: true, // Ensure cookies, including the HTTP-only token, are sent
                });
    
                // Decrement remaining attempts and set the uploaded status
                setRemainingAttempts((prev) => (prev - 1)); // Decrement remaining attempts
                setIsUploaded(true); // Set to true after successful upload
                setFile(null); // Reset file state

            } else {
                alert(`${file.name} Upload Unsuccessful`);
            }
        } catch (error) {
            alert(`Error Uploading File: ${error.message}`);
        }
    };
    

    //Handle logout
    const logout = async ()=>{
        try{
            const response = await axios.post('http://localhost:8081/logout', {}, {
                withCredentials: true // Send the request with cookies
            });

            if(response.status === 200){
                alert('logout successful');
                setToken(null);//clear the token
                navigate('/login')//redirect to the login page
            }else{
                alert('logout unsuccessfully!')
            }
        }catch(error){
            console.error("Logout error:", error);
            alert("Error logging out, please try again.");
        }
    }
  
    return (
        <div className={styles.Container}>
          <div className={styles.center_container}>
            {/* do not change this part */}
            <button className={styles.main_btn} onClick={openDialog}>Upload Identity</button>
            <dialog ref={dialogRef} className={styles.uploadIdentityDialog}>
                <div className={styles.file_upload_container}>

                    <div className={styles.top}>
                        <h3 className={styles.title}>Upload Photo</h3>
                    </div>
                    <div>
                        <h2 className={styles.remaining_attempts}>Remaining Attempts: {remainingAttempts}</h2>
                    </div>

                    <div className={styles.middle}>
                        <label className={styles.file_drop_area} onDrop={handleFileDrop} onDragOver={handleFileDrop}>
                            <LuFilePlus2 className={styles.icon} />
                            <p className={styles.description}>Drop your image here <span className={styles.color_primary}>browse</span></p>
                            <p className={styles.text_muted}>Max. File Size 2 MB</p>
                            <input id='uploadFile' type="file" onChange={handleFileInput}  disabled={remainingAttempts <= 0} accept='.jpeg, .jpg, .png' />
                        </label>
                        <div className={styles.preview_area}>
                            {file && ( // Updated to check if file is defined
                                <div className={styles.preview_card}>
                                    <div className={styles.column_avater}>
                                    {isImage(file) ? <img src={URL.createObjectURL(file)} alt={file.name}/> :<BsFileEarmark/>}
                                    </div>
                                    <div className={styles.column}>
                                        <p className={styles.name}>{file.name}</p>
                                        <p className={styles.text_muted_size}>{fileSize(file.size)}</p>
                                    </div>
                                    <div className={styles.column_last}>
                                        <LiaTimesSolid className={styles.cancel_icon} onClick={handleFileDelete} />
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                    <div className={styles.bottom}>
                        <button id={styles.btn} onClick={closeDialog}>Cancel</button>
                        <button id="btn-upload" className={styles.btn_primary} onClick={handleUpload} disabled={remainingAttempts <= 0 || !file} >Save</button>
                    </div>
                </div>
            </dialog>

            {/* start from here */}
            <button className={styles.main_btn}><Link to="/camera">Take Picture</Link></button>
            <button className={styles.main_btn} onClick={logout}>Logout</button>
           </div>
    </div>
    );
}

export default Homepage;
