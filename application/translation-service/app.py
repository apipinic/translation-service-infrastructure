from flask import Flask, request, jsonify, render_template, redirect
import whisper
import os
from deep_translator import GoogleTranslator
from flask_jwt_extended import JWTManager, decode_token
import subprocess

app = Flask(__name__)

# JWT Secret Key
app.config['JWT_SECRET_KEY'] = 'default-jwt-secret-key'
jwt = JWTManager(app)

# Load Whisper Model (Achtung: kann groß sein, ggf. base / tiny)
model = whisper.load_model("base")

def extract_user_info():
    """
    Liest den Token aus den Query-Parametern (?token=...) und dekodiert ihn.
    Gibt die E-Mail als String zurück, falls Token gültig - sonst None.
    """
    token = request.args.get('token')
    if token:
        try:
            decoded = decode_token(token)
            if isinstance(decoded["sub"], dict) and "email" in decoded["sub"]:
                return decoded["sub"]["email"]
        except Exception as e:
            print("Invalid Token:", e)
    return None

@app.before_request
def check_jwt():
    """
    Bevor irgendein Request verarbeitet wird:
    - Falls Pfad == /health oder /static, kein Token nötig
    - Sonst Token prüfen. Falls invalid/keiner da -> redirect zum Login-Service.
    """
    if request.path.startswith("/static"):
        return  # statische Dateien (CSS/JS/Images) frei ausliefern
    if request.path == "/health":
        return  # health-check freigeben

    user_email = extract_user_info()
    if not user_email:
        # Kein gültiger Token -> zurück zum Login-Service
        return redirect("http://localhost:5000/")

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
        print(f"File saved at: {file_path}")

        # Bei MP3 oder MP4 in WAV umwandeln (ffmpeg nötig)
        if file.filename.lower().endswith('.mp3') or file.filename.lower().endswith('.mp4'):
            converted_path = file_path.rsplit('.', 1)[0] + ".wav"
            subprocess.run(["ffmpeg", "-i", file_path, converted_path], check=True)
            os.remove(file_path)
            file_path = converted_path
            print(f"File converted to WAV: {file_path}")

        # Whisper Transcription
        result = model.transcribe(file_path)
        transcription = result.get('text', '')
        print(f"Transcription: {transcription}")

        # Translation (Englisch -> Deutsch)
        translation = GoogleTranslator(source='en', target='de').translate(transcription)
        print(f"Translation: {translation}")

        os.remove(file_path)  # Datei aufräumen

        return jsonify({"transcription": transcription, "translation": translation})

    except Exception as e:
        print(f"Error during transcription: {str(e)}")
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
        print(f"Translation Error: {str(e)}")
        return jsonify({"error": "Translation failed due to server error."}), 500

@app.route("/health")
def health():
    return "OK", 200

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5001, debug=True)
