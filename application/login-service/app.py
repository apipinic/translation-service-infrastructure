from flask import Flask, request, redirect, url_for, render_template
from flask_login import LoginManager, login_user, logout_user, current_user, UserMixin, login_required
from flask_jwt_extended import JWTManager, create_access_token
from oauthlib.oauth2 import WebApplicationClient
import requests
import os
import json
import logging

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Logging konfigurieren
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Flask App konfigurieren
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "default-secret-key")
app.config['JWT_SECRET_KEY'] = os.environ.get("JWT_SECRET_KEY", "default-jwt-secret-key")

# JWT-Manager
jwt = JWTManager(app)

# Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Google OAuth2 Konfiguration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "default-client-id")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "default-client-secret")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

client = WebApplicationClient(GOOGLE_CLIENT_ID)

# User Model
class User(UserMixin):
    def __init__(self, id_, name, email):
        self.id = id_
        self.name = name
        self.email = email

# In-Memory-User-Datenbank
users = {}

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

@app.route("/login")
def login():
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    redirect_uri = url_for("callback", _external=True)
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=redirect_uri,
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@app.route("/login/callback")
def callback():
    code = request.args.get("code")
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    redirect_uri = url_for("callback", _external=True)
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=redirect_uri,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )
    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers)

    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        users_name = userinfo_response.json()["given_name"]
        user = User(unique_id, users_name, users_email)

        # User in "Datenbank" speichern
        users[unique_id] = user
        # Flask-Login-Session
        login_user(user)

        # JWT-Token erstellen (Identity = dict mit ID und Email)
        user_info = {"id": unique_id, "email": users_email}
        access_token = create_access_token(identity=user_info)

        # Weiterleitung zum Transcribe-Service mit Token
        return redirect(f"http://localhost:5001/?token={access_token}")
    else:
        return "User email not available or not verified by Google.", 400

@app.route("/")
def index():
    if current_user.is_authenticated:
        return (
            f"Hello {current_user.name}! "
            f"<a href='/logout'>Logout</a>"
        )
    else:
        return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route("/health")
def health():
    return "OK", 200

if __name__ == "__main__":
    # Starte auf Port 5000
    app.run(host='0.0.0.0', port=5000, debug=True)
