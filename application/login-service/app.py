from flask import Flask, render_template, redirect, url_for, request, jsonify, make_response
from flask_login import LoginManager, login_user, logout_user, current_user, UserMixin, login_required
from flask_jwt_extended import JWTManager, create_access_token, decode_token
from oauthlib.oauth2 import WebApplicationClient
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_cors import CORS
import requests
import os
import json
import logging

# Enable OAuth for development over HTTP
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Logging setup
logging.basicConfig(level=logging.DEBUG)

# Flask app setup
app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = os.environ.get("SECRET_KEY", "default-secret-key")
app.config['JWT_SECRET_KEY'] = os.environ.get("JWT_SECRET_KEY", "default-jwt-secret-key")

# Secure session cookies
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"

# Proxy settings for HTTPS
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1,
    x_port=1,
    x_prefix=1,
)

app.config['SECURE_PROXY_SSL_HEADER'] = ('X-Forwarded-Proto', 'https')

# JWT setup
jwt = JWTManager(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Google OAuth setup
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "default-client-id")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "default-client-secret")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
client = WebApplicationClient(GOOGLE_CLIENT_ID)

# User storage
users = {}

class User(UserMixin):
    def __init__(self, id_, name, email):
        self.id = id_
        self.name = name
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

@app.before_request
def log_headers():
    logging.debug(f"Headers: {dict(request.headers)}")

def get_google_provider_cfg():
    """
    Retrieves Google's OAuth 2.0 configuration.
    """
    logging.debug("Fetching Google provider configuration.")
    return requests.get(GOOGLE_DISCOVERY_URL).json()

@app.route("/login")
def login():
    google_provider_cfg = get_google_provider_cfg()
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
    try:
        code = request.args.get("code")
        logging.debug(f"Authorization code received: {code}")
        google_provider_cfg = get_google_provider_cfg()
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
        logging.debug(f"Token response received: {token_response.json()}")
        client.parse_request_body_response(json.dumps(token_response.json()))
        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
        uri, headers, body = client.add_token(userinfo_endpoint)
        userinfo_response = requests.get(uri, headers=headers)
        logging.debug(f"User info received: {userinfo_response.json()}")

        if userinfo_response.json().get("email_verified"):
            unique_id = userinfo_response.json()["sub"]
            users_email = userinfo_response.json()["email"]
            users_name = userinfo_response.json()["given_name"]

            # Create user
            user = User(unique_id, users_name, users_email)
            users[unique_id] = user
            login_user(user)

            # JWT Token (use unique_id as a string)
            access_token = create_access_token(identity=str(unique_id))  # Ensures identity is a string
            logging.debug(f"JWT token generated: {access_token}")

            translation_service_url = f"https://translation-cloud.at/transcribe?token={access_token}"
            return redirect(translation_service_url)

        else:
            logging.error("User email not verified.")
            return render_template("error.html", error="Email konnte nicht verifiziert werden."), 400
    except Exception as e:
        logging.error(f"Error during login callback: {e}")
        return render_template("error.html", error="Login fehlgeschlagen."), 400


@app.route("/")
def index():
    access_token = request.cookies.get("token")  # JWT token from cookies
    logging.debug(f"Access token on homepage: {access_token}")

    if access_token:
        try:
            # Validate token
            decoded_token = decode_token(access_token)
            logging.debug(f"Decoded token: {decoded_token}")
            user_id = str(decoded_token.get("sub", ""))  # Ensure `sub` is a string
            if not user_id:
                raise ValueError("The 'sub' field in the token is missing or invalid.")
            user = users.get(user_id)
            if not user:
                raise ValueError("User not found.")
            
            # Render the index page with the user's name
            return render_template("index.html", username=user.name)
        except Exception as e:
            logging.error(f"Invalid token: {e}")
            # Invalid token -> redirect to login page
            return render_template("login.html", error="Ungültiges oder abgelaufenes Token.")
    else:
        # No token -> show login page
        return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    response = render_template("login.html")
    response = make_response(response)
    response.delete_cookie("token")  # JWT token
    response.delete_cookie("session")  # Session cookie
    logging.debug("User logged out and cookies cleared.")
    return response

@app.route("/health")
def health():
    return "OK Login Service", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
