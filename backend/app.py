from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from datetime import timedelta
import re
from itsdangerous import URLSafeTimedSerializer
from flask import send_from_directory

app = Flask(
    __name__,
    static_folder='../sky',
    static_url_path=''
)

app.secret_key = "secret123"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
CORS(app, supports_credentials=True)

app.permanent_session_lifetime = timedelta(days=7)


# ========================
# DATABASE MODEL
# ========================
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))

class Opportunity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    duration = db.Column(db.String(100))
    start_date = db.Column(db.String(100))
    description = db.Column(db.Text)
    skills = db.Column(db.String(300))
    category = db.Column(db.String(100))
    future = db.Column(db.String(200))
    max_applicants = db.Column(db.String(50))
    admin_id = db.Column(db.Integer)

@app.route('/')
def home():
    return send_from_directory('../sky', 'admin.html')
# ========================
# SIGNUP API
# ========================
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json

    fullname = data.get('fullname')
    email = data.get('email')
    password = data.get('password')
    confirm = data.get('confirm')

    # All fields required
    if not fullname or not email or not password or not confirm:
        return jsonify({"error": "All fields are required"}), 400

    # Email validation
    email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'

    if not re.match(email_pattern, email):
        return jsonify({"error": "Invalid email format"}), 400

    # Password length
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    # Password match
    if password != confirm:
        return jsonify({"error": "Passwords do not match"}), 400

    # Check duplicate email
    existing = Admin.query.filter_by(email=email).first()

    if existing:
        return jsonify({"error": "Account already exists"}), 400

    # Encrypt password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Save user
    new_admin = Admin(
        fullname=fullname,
        email=email,
        password=hashed_password
    )

    db.session.add(new_admin)
    db.session.commit()

    return jsonify({
        "message": "Signup successful",
        "redirect": "/login"
    }), 201

# ========================
# LOGIN API
# ========================
@app.route('/login', methods=['POST'])
def login():
    data = request.json

    email = data.get('email')
    password = data.get('password')
    remember = data.get('remember')

    user = Admin.query.filter_by(email=email).first()

    if user and bcrypt.check_password_hash(user.password, password):

        session['admin_id'] = user.id

        if remember:
            session.permanent = True

        return jsonify({
            "message": "Login successful",
            "name": user.fullname
        }), 200

    return jsonify({
        "error": "Invalid email or password"
    }), 401

serializer = URLSafeTimedSerializer(app.secret_key)


# ========================
# FORGOT PASSWORD
# ========================
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')

    user = Admin.query.filter_by(email=email).first()

    # Always same message
    if user:
        token = serializer.dumps(email, salt='reset-password')

        # internally generated link
        reset_link = f"http://127.0.0.1:5000/reset-password/{token}"

        print("Reset Link:", reset_link)

    return jsonify({
        "message": "If the email exists, a reset link has been generated."
    }), 200

# ========================
# GET ALL OPPORTUNITIES
# ========================
@app.route('/opportunities', methods=['GET'])
def get_opportunities():

    if 'admin_id' not in session:
        return jsonify([]), 401

    all_data = Opportunity.query.filter_by(
        admin_id=session['admin_id']
    ).all()

    result = []

    for item in all_data:
        result.append({
            "id": item.id,
            "name": item.name,
            "duration": item.duration,
            "start_date": item.start_date,
            "description": item.description,
            "skills": item.skills,
            "category": item.category,
            "future": item.future,
            "max_applicants": item.max_applicants
        })

    return jsonify(result), 200

# ========================
# ADD OPPORTUNITY
# ========================
@app.route('/add-opportunity', methods=['POST'])
def add_opportunity():

    if 'admin_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json

    name = data.get('name')
    duration = data.get('duration')
    start_date = data.get('start_date')
    description = data.get('description')
    skills = data.get('skills')
    category = data.get('category')
    future = data.get('future')
    max_applicants = data.get('max_applicants')

    # required validation
    if not name or not duration or not start_date or not description or not skills or not category or not future:
        return jsonify({"error": "All required fields must be filled"}), 400

    new_item = Opportunity(
        name=name,
        duration=duration,
        start_date=start_date,
        description=description,
        skills=skills,
        category=category,
        future=future,
        max_applicants=max_applicants,
        admin_id=session['admin_id']
    )

    db.session.add(new_item)
    db.session.commit()

    return jsonify({
        "message": "Opportunity added successfully"
    }), 201

# ========================
# DELETE OPPORTUNITY
# ========================
@app.route('/delete-opportunity/<int:id>', methods=['DELETE'])
def delete_opportunity(id):

    if 'admin_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    item = Opportunity.query.get(id)

    if not item:
        return jsonify({"error": "Not found"}), 404

    if item.admin_id != session['admin_id']:
        return jsonify({"error": "Unauthorized"}), 403

    db.session.delete(item)
    db.session.commit()

    return jsonify({
        "message": "Deleted successfully"
    }), 200

# ========================
# EDIT OPPORTUNITY
# ========================
@app.route('/edit-opportunity/<int:id>', methods=['PUT'])
def edit_opportunity(id):

    if 'admin_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    item = Opportunity.query.get(id)

    if not item:
        return jsonify({"error": "Not found"}), 404

    if item.admin_id != session['admin_id']:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json

    item.name = data.get('name')
    item.duration = data.get('duration')
    item.start_date = data.get('start_date')
    item.description = data.get('description')
    item.skills = data.get('skills')
    item.category = data.get('category')
    item.future = data.get('future')
    item.max_applicants = data.get('max_applicants')

    db.session.commit()

    return jsonify({
        "message": "Updated successfully"
    }), 200

# ========================
# LOGOUT
# ========================
@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return jsonify({
        "message": "Logged out successfully"
    }), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True)