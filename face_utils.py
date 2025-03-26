import cv2
import dlib
import numpy as np
import json
from sklearn.metrics.pairwise import cosine_similarity

# Load dlib models
detector = dlib.get_frontal_face_detector()
shape_predictor = dlib.shape_predictor("models/shape_predictor_68_face_landmarks.dat")
face_encoder = dlib.face_recognition_model_v1("models/dlib_face_recognition_resnet_model_v1.dat")

def normalize_vector(vec):
    """ Normalize a 128D face encoding. """
    return vec / np.linalg.norm(vec)

def face_encodings_from_image(image_data):
    """
    Extract face embeddings using dlib.
    
    Args:
        image_data: Base64 encoded image data or bytes
    
    Returns:
        Face encoding as a JSON string or None if no face found
    """
    try:
        # Convert image data to numpy array
        nparr = np.frombuffer(image_data, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        # Convert to RGB
        rgb_img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)

        # Detect faces
        faces = detector(rgb_img)

        if len(faces) == 0:
            print("No face detected!")
            return None

        # Get face landmarks
        shape = shape_predictor(rgb_img, faces[0])

        # Compute and normalize face encoding
        face_encoding = np.array(face_encoder.compute_face_descriptor(rgb_img, shape))
        face_encoding = normalize_vector(face_encoding)

        return json.dumps(face_encoding.tolist())

    except Exception as e:
        print(f"Error in face_encodings_from_image: {str(e)}")
        return None

def compare_faces(stored_encoding, captured_encoding, tolerance=0.5):
    """
    Compare stored face encoding with captured encoding using cosine similarity.

    Args:
        stored_encoding: JSON string or list of stored face encoding
        captured_encoding: JSON string or list of captured face encoding
        tolerance: Threshold for matching (0.5-0.6 recommended for cosine similarity)

    Returns:
        Boolean indicating if faces match
    """
    try:
        # Ensure stored_encoding is converted to a NumPy array
        if isinstance(stored_encoding, str):
            stored_encoding = json.loads(stored_encoding)
        if not isinstance(stored_encoding, list):
            raise ValueError("Stored encoding should be a list!")

        # Ensure captured_encoding is converted to a NumPy array
        if isinstance(captured_encoding, str):
            captured_encoding = json.loads(captured_encoding)
        if not isinstance(captured_encoding, list):
            raise ValueError("Captured encoding should be a list!")

        # Convert to NumPy arrays
        stored_features = np.array(stored_encoding)
        captured_features = np.array(captured_encoding)

        # Normalize features
        stored_features = normalize_vector(stored_features)
        captured_features = normalize_vector(captured_features)

        # Compute cosine similarity
        similarity = cosine_similarity([stored_features], [captured_features])[0][0]
        print(f"Cosine Similarity Score: {similarity:.4f}")

        # Check if similarity exceeds tolerance
        match = similarity > tolerance
        print("Match!" if match else "No Match!")
        return match

    except json.JSONDecodeError:
        print("JSON Decode Error: Make sure encodings are correctly formatted JSON strings.")
    except ValueError as ve:
        print(f"ValueError: {ve}")
    except Exception as e:
        print(f"Unexpected Error in compare_faces: {str(e)}")

    return False  # Default to no match if an error occurs
