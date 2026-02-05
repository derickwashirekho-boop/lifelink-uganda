from flask import Flask, render_template, request, redirect, url_for, abort
from pymongo import MongoClient
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
from bson.objectid import ObjectId
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = "lifelink_secret_key"

bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# MongoDB 
client = MongoClient(os.environ.get("MONGODB_URI"))
db = client["lifelink"]

incidents = db["incidents"]
users = db["users"]

# USER MODEL 
class User(UserMixin):
    def __init__(self, user):
        self.id = str(user["_id"])
        self.username = user["username"]
        self.role = user["role"]

@login_manager.user_loader
def load_user(user_id):
    user = users.find_one({"_id": ObjectId(user_id)})
    return User(user) if user else None

# ROLE DECORATOR
def role_required(role):
    def wrapper(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role != role:
                abort(403)
            return fn(*args, **kwargs)
        return decorated
    return wrapper

# ROUTES 
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/report", methods=["POST"])
def report():
    incidents.insert_one({
        "name": request.form["name"],
        "phone": request.form["phone"],
        "type": request.form["type"],
        "location": request.form["location"],
        "description": request.form["description"],
        "status": "Pending",
        "time": datetime.now()
    })
    return redirect("/")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = users.find_one({"username": request.form["username"]})
        if user and bcrypt.check_password_hash(user["password"], request.form["password"]):
            login_user(User(user))
            return redirect("/dashboard")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
@login_required
@role_required("admin")
def register():
    if request.method == "POST":
        if users.find_one({"username": request.form["username"]}):
            return "User already exists"

        users.insert_one({
            "username": request.form["username"],
            "password": bcrypt.generate_password_hash(
                request.form["password"]
            ).decode("utf-8"),
            "role": request.form["role"]
        })
        return redirect("/dashboard")

    return render_template("register.html")

@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role not in ["admin", "responder"]:
        abort(403)

    return render_template(
        "dashboard.html",
        incidents=list(incidents.find())
    )

@app.route("/update/<id>/<status>")
@login_required
@role_required("admin")
def update_status(id, status):
    incidents.update_one(
        {"_id": ObjectId(id)},
        {"$set": {"status": status}}
    )
    return redirect("/dashboard")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")

@app.errorhandler(403)
def forbidden(e):
    return "<h3>403 – Access Denied</h3>", 403

if __name__ == "__main__":
    app.run(debug=True)
