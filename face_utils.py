import cv2
import dlib
import numpy as np
import face_recognition
import json
from sklearn.metrics.pairwise import cosine_similarity

# Configure dlib face detector
detector = dlib.get_frontal_face_detector()

# Load the face recognition model
FACE_ENCODING_MODEL = "models/dlib_face_recognition_resnet_model_v1.dat"
SP_MODEL = "models/shape_predictor_68_face_landmarks.dat"

face_encoder = dlib.face_recognition_model_v1(FACE_ENCODING_MODEL)
shape_predictor = dlib.shape_predictor(SP_MODEL)

FEATURE_LENGTH = 128  # FaceNet/dlib generates 128D embeddings


def face_encodings_from_image(image_data):
    """
    Extract face embeddings using dlib's deep learning model.
    
    Args:
        image_data: Base64 encoded image data or bytes
    
    Returns:
        Face encoding as a JSON string or None if no face found
    """
    try:
        # Convert base64 to image
        nparr = np.frombuffer(image_data, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        # Convert to RGB
        rgb_img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)

        # Detect faces
        faces = detector(rgb_img)

        if len(faces) == 0:
            return None

        # Get face landmarks
        shape = shape_predictor(rgb_img, faces[0])

        # Compute face encoding
        face_encoding = np.array(face_encoder.compute_face_descriptor(rgb_img, shape))

        return json.dumps(face_encoding.tolist())

    except Exception as e:
        print(f"Error in face_encodings_from_image: {str(e)}")
        return None


def compare_faces(stored_encoding, captured_encoding, tolerance=0.3):
    """
    Compare stored face encoding with captured encoding using cosine similarity.

    Args:
        stored_encoding: JSON string or list of stored face encoding
        captured_encoding: JSON string or list of captured face encoding
        tolerance: Threshold for matching (higher = stricter)

    Returns:
        Boolean indicating if faces match
    """
    try:
        # Debugging Logs
        print(f"Stored Encoding Type: {type(stored_encoding)}, Value: {stored_encoding[:10]}...")  # Partial print
        print(f"Captured Encoding Type: {type(captured_encoding)}, Value: {captured_encoding[:10]}...")  

        # Ensure stored_encoding is converted to a NumPy array
        if isinstance(stored_encoding, str):
            stored_encoding = json.loads(stored_encoding)
            print("Converted stored_encoding from JSON string.")
        if not isinstance(stored_encoding, list):
            raise ValueError("Error: Stored encoding should be a list!")

        # Ensure captured_encoding is converted to a NumPy array
        if isinstance(captured_encoding, str):
            captured_encoding = json.loads(captured_encoding)
            print("Converted captured_encoding from JSON string.")
        if not isinstance(captured_encoding, list):
            raise ValueError("Error: Captured encoding should be a list!")

        # Convert to NumPy arrays
        stored_features = np.array(stored_encoding)
        captured_features = np.array(captured_encoding)

        # Ensure the arrays have the correct shape
        if stored_features.shape != captured_features.shape:
            raise ValueError(f"Shape Mismatch: Stored {stored_features.shape}, Captured {captured_features.shape}")

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

