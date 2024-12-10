from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from datetime import datetime, timezone
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'my_super_secret_key_12345'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
with app.app_context():
    db.create_all()
def add_user(username, password):
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')  
    new_user = User(username=username, password=hashed_password)
    with app.app_context():
        db.session.add(new_user)
        db.session.commit()
    print(f"Korisnik {username} je uspešno dodat u bazu!")
@app.route('/add_user', methods=['POST'])
def create_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"message": "Username and password are required!"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already exists!"}), 400
    add_user(username, password)
    return jsonify({"message": f"User {username} added successfully!"}), 201
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"message": "Username and password are required!"}), 400
    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"message": "Invalid username or password"}), 401
    access_token = create_access_token(identity=user.username)
    print(f"Generisan token za korisnika {username}: {access_token}")
    return jsonify({"token": access_token}), 200
@app.route('/identify', methods=['GET'])
@jwt_required()
def identify():
    try:
        current_user = get_jwt_identity()
        token_info = get_jwt()
        expires_at = datetime.fromtimestamp(token_info['exp'], tz=timezone.utc)
        print(f"Validacija tokena za korisnika: {current_user}")
        print(f"Token ističe: {expires_at}")
        return jsonify({
            "message": f"Token is valid for user: {current_user}",
            "expires_at": expires_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        }), 200
    except Exception as e:
        print(f"Greška pri proveri tokena: {e}")
        return jsonify({"message": "Invalid or expired token"}), 401
if __name__ == '__main__':
    app.run(debug=True)