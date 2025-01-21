from flask import Flask, request, jsonify, render_template, redirect
import whisper
import os
from deep_translator import GoogleTranslator
from flask_jwt_extended import JWTManager, decode_token
from flask_cors import CORS
import subprocess
import logging

# Logging setup
logging.basicConfig(level=logging.DEBUG)

# Initialize Flask app
app = Flask(__name__)

# Load JWT secret key from environment variable
jwt_secret_key = os.environ.get("JWT_SECRET_KEY")
if not jwt_secret_key:
    raise RuntimeError("JWT_SECRET_KEY is not set.")
app.config['JWT_SECRET_KEY'] = jwt_secret_key

# Initialize CORS for HTTPS requests
CORS(app, resources={r"/*": {"origins": "*"}})

# Initialize JWT manager
jwt = JWTManager(app)

# Load Whisper model
model = whisper.load_model("base")


def extract_user_info():
    """
    Extract user information from the provided JWT token.
    """
    token = request.args.get('token')
    if token:
        try:
            logging.debug(f"Received JWT Token: {token}")
            decoded = decode_token(token)
            logging.debug(f"Decoded JWT Token: {decoded}")
            return decoded.get("sub")  # `sub` should contain the unique user ID
        except Exception as e:
            logging.error(f"Invalid Token Error: {e}")
    else:
        logging.warning("No token provided in the request.")
    return None


@app.before_request
def check_jwt():
    """
    Verify the JWT token before processing any request, except for allowed paths.
    """
    allowed_paths = ["/health", "/test_token", "/test", "/", "/transcribe"]
    if any(request.path.startswith(path) for path in allowed_paths):
        return
    user_email = extract_user_info()
    if not user_email:
        login_service_url = os.environ.get("LOGIN_SERVICE_URL", "https://localhost:5000")
        return redirect(login_service_url)


@app.route("/")
def index():
    """
    Render the main interface for transcription.
    """
    token = request.args.get("token")
    if token:
        try:
            user_info = decode_token(token)
            logging.debug(f"User info from token: {user_info}")
        except Exception as e:
            logging.error(f"Invalid token: {e}")
            return "Invalid token", 401
    return render_template("index.html")


@app.route('/transcribe', methods=['POST'])
def transcribe():
    """
    Handle file upload for transcription and translation.
    """
    try:
        # Validate token
        token = request.args.get('token')
        if not token:
            logging.warning("No token found in the request.")
            return jsonify({"error": "Token is missing"}), 401

        user_email = extract_user_info()
        if not user_email:
            logging.error("Token validation failed or user email is missing.")
            return jsonify({"error": "Invalid token"}), 401

        # Log the user making the request
        logging.info(f"Transcription request by user: {user_email}")

        # Check if file is uploaded
        if 'file' not in request.files:
            logging.warning("No file uploaded in the request.")
            return jsonify({"error": "No file uploaded"}), 400

        # Save the file
        file = request.files['file']
        os.makedirs("uploads", exist_ok=True)
        file_path = os.path.join("uploads", file.filename)
        file.save(file_path)
        logging.debug(f"File saved to {file_path}")

        # Convert file to WAV format if necessary
        if file.filename.lower().endswith(('.mp3', '.mp4')):
            converted_path = file_path.rsplit('.', 1)[0] + ".wav"
            subprocess.run(["ffmpeg", "-i", file_path, converted_path], check=True)
            os.remove(file_path)
            file_path = converted_path
            logging.debug(f"File converted to WAV: {file_path}")

        # Transcribe the audio file
        result = model.transcribe(file_path)
        transcription = result.get('text', '')
        logging.info(f"Transcription result: {transcription}")

        # Translate the transcription
        translation = GoogleTranslator(source='en', target='de').translate(transcription)
        logging.info(f"Translation result: {translation}")
        os.remove(file_path)

        # Return the results
        return jsonify({"transcription": transcription, "translation": translation})

    except Exception as e:
        logging.error(f"Error during transcription: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/health")
def health():
    """
    Health check endpoint for the service.
    """
    return "OK Translation Service", 200


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5001, debug=True)