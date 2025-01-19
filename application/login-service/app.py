from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_login import LoginManager, login_user, logout_user, current_user, UserMixin, login_required
from flask_jwt_extended import JWTManager, create_access_token
from oauthlib.oauth2 import WebApplicationClient
from werkzeug.middleware.proxy_fix import ProxyFix
import requests
import os
import json
import logging

# Aktivieren von unsicherem Transport für lokale Entwicklung (nur für Debugging)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Logging-Konfiguration
logging.basicConfig(level=logging.DEBUG)

# Flask App Konfiguration
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "default-secret-key")
app.config['JWT_SECRET_KEY'] = os.environ.get("JWT_SECRET_KEY", "default-jwt-secret-key")
app.config['SERVER_NAME'] = "translation-cloud.at"  # Setze den korrekten Servernamen

# ProxyFix anwenden, um Header korrekt zu verarbeiten
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1,
    x_port=1,
    x_prefix=1,
)

# JWT Manager initialisieren
jwt = JWTManager(app)

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # Standardweiterleitung, falls nicht eingeloggt

# Google OAuth2 Konfiguration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "default-client-id")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "default-client-secret")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

client = WebApplicationClient(GOOGLE_CLIENT_ID)

# Service URLs
TRANSCRIBE_URL = os.environ.get("TRANSCRIBE_URL", "http://translation-service.kundea.svc.cluster.local/transcribe")
TRANSLATE_LIVE_URL = os.environ.get("TRANSLATE_LIVE_URL", "http://translation-service.kundea.svc.cluster.local/translate_live")

# User Model
class User(UserMixin):
    def __init__(self, id_, name, email):
        self.id = id_
        self.name = name
        self.email = email

users = {}

@login_manager.user_loader
def load_user(user_id):
    user = users.get(user_id)
    if not user:
        logging.debug(f"User not found: {user_id}")
    return user

@app.before_request
def enforce_https():
    """Erzwinge HTTPS-Weiterleitung."""
    if request.headers.get('X-Forwarded-Proto', 'http') != 'https':
        url = request.url.replace("http://", "https://", 1)
        logging.debug(f"Redirecting to HTTPS: {url}")
        return redirect(url, code=301)

@app.before_request
def log_headers():
    """Logge eingehende Header für Debugging."""
    logging.debug(f"Headers: {dict(request.headers)}")

@app.route("/login")
def login():
    """Startet den Google OAuth2 Login-Prozess."""
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    redirect_uri = url_for("callback", _external=True, _scheme="https")
    logging.debug(f"Redirect URI for login: {redirect_uri}")
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=redirect_uri,
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@app.route("/login/callback")
def callback():
    """Callback nach erfolgreichem OAuth2-Login."""
    try:
        code = request.args.get("code")
        google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
        token_endpoint = google_provider_cfg["token_endpoint"]

        redirect_uri = url_for("callback", _external=True, _scheme="https")
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

            users[unique_id] = user
            login_user(user)

            user_info = {"id": unique_id, "email": users_email}
            token = create_access_token(identity=user_info)

            logging.debug(f"User logged in: {user.name}, ID: {user.id}")
            response = redirect(url_for("index"))
            response.set_cookie("token", token, secure=True, httponly=True, samesite="Strict")
            return response
        else:
            logging.error("User email not verified.")
            return "User email not available or not verified by Google.", 400
    except Exception as e:
        logging.error(f"Error during login callback: {e}")
        return "An error occurred during login.", 500

@app.route("/")
@login_required
def index():
    logging.debug(f"User authenticated: {current_user.is_authenticated}")
    return render_template(
        "index.html",
        username=current_user.name,
        transcribe_url=TRANSCRIBE_URL,
        translate_live_url=TRANSLATE_LIVE_URL,
    )

@app.route("/logout")
@login_required
def logout():
    logout_user()
    response = redirect(url_for("login"))
    response.delete_cookie("token")
    logging.debug("User logged out.")
    return response

@app.route("/health")
def health():
    return "OK Login Service", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
