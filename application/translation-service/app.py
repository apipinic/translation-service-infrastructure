from flask import Flask, request, jsonify, render_template, redirect
import whisper
import os
from deep_translator import GoogleTranslator
from flask_jwt_extended import JWTManager, decode_token
from flask_cors import CORS
import subprocess
import logging
import time

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


@app.route('/transcribe', methods=['GET', 'POST'])
def transcribe():
    token = request.args.get('token')
    if not token:
        return jsonify({"msg": "Token not found! Please login again."}), 401

    try:
        # Decode and log the token
        decoded_token = decode_token(token)
        logging.debug(f"Decoded token: {decoded_token}")

        # Extract user info from the token
        user_id = decoded_token.get("sub")
        user_name = decoded_token.get("name", "Unknown User")  # Default to "Unknown User" if name is missing

        # Log extracted user details for debugging
        logging.debug(f"User ID: {user_id}, User Name: {user_name}")

        # Check for token expiration
        if decoded_token["exp"] < int(time.time()):
            return jsonify({"msg": "Token has expired. Please login again."}), 401

        if request.method == 'GET':
            # Pass username to the template for rendering
            return render_template("index.html", username=user_name, token=token)

        elif request.method == 'POST':
            # Handle file uploads and transcription
            if 'file' not in request.files:
                return jsonify({"msg": "No file uploaded"}), 400

            # Save the uploaded file
            file = request.files['file']
            os.makedirs("uploads", exist_ok=True)
            file_path = os.path.join("uploads", file.filename)
            file.save(file_path)
            logging.debug(f"File saved to {file_path}")

            # Convert to WAV format if necessary
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
            return jsonify({
                "user_id": user_id,
                "transcription": transcription,
                "translation": translation
            }), 201

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return jsonify({"msg": "An error occurred while processing the request"}), 500
    
@app.route('/translate_live', methods=['POST'])
def translate_live():
    token = request.args.get('token')
    if not token:
        return jsonify({"msg": "Token not found! Please login again."}), 401

    try:
        # Validate the token
        decoded_token = decode_token(token)
        user_id = decoded_token.get("sub")

        # Check for token expiration
        if decoded_token["exp"] < int(time.time()):
            return jsonify({"msg": "Token has expired. Please login again."}), 401

        # Process live transcription data
        request_data = request.get_json()
        text = request_data.get("text", "")
        if not text:
            return jsonify({"msg": "No text provided for translation"}), 400

        # Translate the text
        translation = GoogleTranslator(source='en', target='de').translate(text)
        logging.info(f"Live Translation: {translation}")

        return jsonify({
            "user_id": user_id,
            "translation": translation
        }), 200

    except Exception as e:
        logging.error(f"An error occurred during live translation: {e}")
        return jsonify({"msg": "An error occurred while processing the request"}), 500



@app.route("/health", methods=["GET"])
def health():
    return "OK Translation Service", 200


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5001, debug=True)
