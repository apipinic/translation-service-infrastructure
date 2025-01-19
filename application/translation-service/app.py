from flask import Flask, request, jsonify, render_template, redirect
import whisper
import os
from deep_translator import GoogleTranslator
from flask_jwt_extended import JWTManager, decode_token
import subprocess
import logging

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
jwt_secret_key = os.environ.get("JWT_SECRET_KEY")
if not jwt_secret_key:
    raise RuntimeError("JWT_SECRET_KEY is not set.")
app.config['JWT_SECRET_KEY'] = jwt_secret_key
jwt = JWTManager(app)

model = whisper.load_model("base")

def extract_user_info():
    token = request.args.get('token')
    if token:
        try:
            decoded = decode_token(token)
            return decoded.get("sub")  # `sub` enthält jetzt die eindeutige Benutzer-ID (String)
        except Exception as e:
            logging.error("Invalid Token: %s", e)
    return None

@app.before_request
def check_jwt():
    if request.path.startswith("/static") or request.path == "/health":
        return
    user_email = extract_user_info()
    if not user_email:
        login_service_url = os.environ.get("LOGIN_SERVICE_URL", "http://localhost:5000")
        return redirect(login_service_url)

@app.route('/transcribe', methods=['POST'])
def transcribe():
    try:
        token = request.args.get('token')
        if not token:
            return jsonify({"error": "Token is missing"}), 401
        user_email = extract_user_info()
        if not user_email:
            return jsonify({"error": "Invalid token"}), 401

        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files['file']
        os.makedirs("uploads", exist_ok=True)
        file_path = os.path.join("uploads", file.filename)
        file.save(file_path)

        if file.filename.lower().endswith(('.mp3', '.mp4')):
            converted_path = file_path.rsplit('.', 1)[0] + ".wav"
            subprocess.run(["ffmpeg", "-i", file_path, converted_path], check=True)
            os.remove(file_path)
            file_path = converted_path

        result = model.transcribe(file_path)
        transcription = result.get('text', '')

        translation = GoogleTranslator(source='en', target='de').translate(transcription)
        os.remove(file_path)

        return jsonify({"transcription": transcription, "translation": translation})

    except Exception as e:
        logging.error("Error during transcription: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route('/translate_live', methods=['POST'])
def translate_live():
    try:
        token = request.args.get('token')
        if not token:
            return jsonify({"error": "Token is missing"}), 401
        user_email = extract_user_info()
        if not user_email:
            return jsonify({"error": "Invalid token"}), 401

        data = request.get_json()
        text = data.get("text", "").strip()
        if not text:
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