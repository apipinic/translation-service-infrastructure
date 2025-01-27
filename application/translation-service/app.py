from flask import Flask, request, jsonify, render_template, redirect
import whisper
import os
from deep_translator import GoogleTranslator
from flask_jwt_extended import JWTManager, decode_token
from flask_cors import CORS
import subprocess
import logging
import time
import boto3
from botocore.exceptions import BotoCoreError, ClientError

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

s3_bucket_name = os.environ.get("S3_BUCKET_NAME")
dynamodb_table_name = os.environ.get("DYNAMODB_TABLE")  

s3_client = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
dynamodb_table = dynamodb.Table(dynamodb_table_name)

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


@app.route('/save_meeting', methods=['POST'])
def save_meeting():
    token = request.args.get('token')  # Hole den Token aus der Anfrage
    if not token:
        return jsonify({"msg": "Token not found! Please login again."}), 401

    try:
        # Token validieren und Benutzerinformationen extrahieren
        decoded_token = decode_token(token)
        user_id = decoded_token.get("sub")

        # Überprüfen, ob der Token abgelaufen ist
        if decoded_token["exp"] < int(time.time()):
            return jsonify({"msg": "Token has expired. Please login again."}), 401

        # Daten vom Frontend empfangen
        data = request.get_json()
        meeting_name = data.get("meeting_name")
        meeting_date = data.get("meeting_date")
        transcription = data.get("transcription")
        translation = data.get("translation")

        # Sicherstellen, dass alle erforderlichen Felder vorhanden sind
        if not all([meeting_name, meeting_date, transcription, translation, user_id]):
            return jsonify({"msg": "Missing required fields"}), 400

        # Dateiinhalt erstellen
        file_content = f"Meeting Name: {meeting_name}\nMeeting Date: {meeting_date}\n\nTranscription:\n{transcription}\n\nTranslation:\n{translation}"
        file_name = f"{meeting_name.replace(' ', '_')}_{meeting_date}.txt"

        # S3-Key mit Benutzer-ID erstellen
        s3_key = f"{user_id}/{file_name}"

        # Datei in S3 speichern
        s3_client.put_object(
            Bucket=s3_bucket_name,
            Key=s3_key,
            Body=file_content.encode("utf-8")
        )

        # Daten in DynamoDB speichern
        dynamodb_table.put_item(
            Item={
                "user_id": user_id,
                "file_name": file_name,
                "meeting_name": meeting_name,
                "meeting_date": meeting_date,
                "s3_key": file_name
            }
        )

        return jsonify({"msg": "Meeting saved successfully", "file_name": file_name}), 200

    except (BotoCoreError, ClientError) as e:
        logging.error(f"Error saving meeting: {e}")
        return jsonify({"msg": "Error saving meeting"}), 500

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return jsonify({"msg": "An unexpected error occurred"}), 500


@app.route('/get_last_meetings', methods=['GET'])
def get_last_meetings():
    try:
        user_id = request.args.get("user_id")
        if not user_id:
            return jsonify({"msg": "User ID is required"}), 400

        # Prefix to filter user's files in the bucket
        s3_prefix = f"{user_id}/"
        response = s3_client.list_objects_v2(
            Bucket=s3_bucket_name,
            Prefix=s3_prefix
        )

        if "Contents" not in response:
            return jsonify({"msg": "No meetings found for this user"}), 200

        meetings = []
        for obj in response["Contents"]:
            file_key = obj["Key"]
            file_name = file_key.split("/")[-1]

            # Parse meeting_name and meeting_date from file name
            if "_" in file_name and file_name.endswith(".txt"):
                parts = file_name.replace(".txt", "").split("_")
                meeting_name = parts[0]
                meeting_date = parts[-1]
            else:
                meeting_name = "Unknown"
                meeting_date = "Unknown"

            meetings.append({
                "file_name": file_name,
                "meeting_name": meeting_name,
                "meeting_date": meeting_date,
                "s3_key": file_key,
                "last_modified": obj["LastModified"].isoformat(),
                "size": obj["Size"]
            })

        return jsonify(meetings), 200

    except Exception as e:
        logging.error(f"Error fetching meetings: {e}")
        return jsonify({"msg": "Error fetching meetings"}), 500

    
@app.route('/download_meeting', methods=['GET'])
def download_meeting():
    """
    Generates a presigned URL for the specified S3 key.
    """
    try:
        token = request.args.get('token')  # Token validation (optional)
        file_name = request.args.get('file_name')
        user_id = decode_token(token).get("sub")  # Extract user ID from the token

        if not file_name:
            return jsonify({"msg": "file_name is required"}), 400

        if not user_id:
            return jsonify({"msg": "Invalid user ID"}), 401

        # Add user-specific prefix to the file key
        s3_key = f"{user_id}/{file_name}"

        # Generate the presigned URL
        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': s3_bucket_name, 'Key': s3_key},
            ExpiresIn=3600  # 1 hour
        )

        return jsonify({"url": presigned_url}), 200

    except Exception as e:
        logging.error(f"Error generating presigned URL: {e}")
        return jsonify({"msg": "Error generating presigned URL"}), 500

    
@app.route('/get_user_info', methods=['GET'])
def get_user_info():
    token = request.args.get('token')
    if not token:
        return jsonify({"msg": "Token not found!"}), 401

    try:
        decoded_token = decode_token(token)
        user_id = decoded_token.get("sub")
        return jsonify({"user_id": user_id}), 200
    except Exception as e:
        logging.error(f"Error decoding token: {e}")
        return jsonify({"msg": "Invalid token"}), 400
    
@app.route('/delete_meeting', methods=['DELETE'])
def delete_meeting():
    """
    Deletes a file from the S3 bucket.
    """
    try:
        token = request.args.get('token')  # optional: Token validation
        file_name = request.args.get('file_name')
        if not file_name:
            return jsonify({"msg": "file_name is required"}), 400

        # Delete the file from S3
        s3_client.delete_object(Bucket=s3_bucket_name, Key=file_name)

        return jsonify({"msg": "File deleted successfully"}), 200

    except Exception as e:
        logging.error(f"Error deleting file: {e}")
        return jsonify({"msg": "Error deleting file"}), 500

@app.route("/health", methods=["GET"])
def health():
    return "OK Translation Service", 200


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5001, debug=True)
