from flask import Flask, request, jsonify, render_template, redirect
import whisper
import os
from deep_translator import GoogleTranslator
from flask_jwt_extended import JWTManager, decode_token
import subprocess
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

# JWT Secret Key
jwt_secret_key = os.environ.get("JWT_SECRET_KEY")
if not jwt_secret_key:
    raise RuntimeError("JWT_SECRET_KEY is not set. Please provide it as an environment variable.")
app.config['JWT_SECRET_KEY'] = jwt_secret_key
jwt = JWTManager(app)

# Load Whisper Model
model = whisper.load_model("base")

def extract_user_info():
    """
    Extracts user information from the JWT token in the query parameter (?token=...).
    Returns the email if the token is valid, otherwise None.
    """
    token = request.args.get('token')
    if token:
        try:
            decoded = decode_token(token)
            if isinstance(decoded["sub"], dict) and "email" in decoded["sub"]:
                return decoded["sub"]["email"]
        except Exception as e:
            logging.error("Invalid Token: %s", e)
    return None

@app.before_request
def check_jwt():
    """
    Validate the JWT token before processing requests.
    Allow unauthenticated access to `/health` and `/static`.
    Redirect to login-service if token is invalid or missing.
    """
    if request.path.startswith("/static") or request.path == "/health":
        return  # Allow health checks and static assets without authentication

    user_email = extract_user_info()
    if not user_email:
        # Redirect to login-service if no valid token is provided
        login_service_url = os.environ.get("LOGIN_SERVICE_URL", "http://localhost:5000")
        return redirect(login_service_url)

# Endpoints

@app.route('/')
def index():
    username = extract_user_info()
    return render_template('index.html', username=username)

@app.route('/transcribe', methods=['POST'])
def transcribe():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files['file']
        if not file.filename.lower().endswith(('.mp3', '.wav', '.mp4')):
            return jsonify({"error": "Unsupported file format. Please upload MP3, MP4, or WAV files only."}), 400

        # Save the uploaded file
        os.makedirs("uploads", exist_ok=True)
        file_path = os.path.join("uploads", file.filename)
        file.save(file_path)

        # Convert to WAV if necessary
        if file.filename.lower().endswith(('.mp3', '.mp4')):
            converted_path = file_path.rsplit('.', 1)[0] + ".wav"
            subprocess.run(["ffmpeg", "-i", file_path, converted_path], check=True)
            os.remove(file_path)
            file_path = converted_path

        # Transcription
        result = model.transcribe(file_path)
        transcription = result.get('text', '')

        # Translation
        translation = GoogleTranslator(source='en', target='de').translate(transcription)

        # Cleanup
        os.remove(file_path)

        return jsonify({"transcription": transcription, "translation": translation})

    except Exception as e:
        logging.error("Error during transcription: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route('/translate_live', methods=['POST'])
def translate_live():
    try:
        data = request.get_json()
        text = data.get("text", "")

        if not text.strip():
            return jsonify({"error": "Empty input text"}), 400

        translation = GoogleTranslator(source='en', target='de').translate(text)
        return jsonify({"translation": translation})

    except Exception as e:
        logging.error("Translation Error: %s", e)
        return jsonify({"error": "Translation failed due to server error."}), 500

@app.route("/health")
def health():
    return "OK Translation Service", 200

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5001, debug=True)
