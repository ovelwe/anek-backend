import os
import random
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()


def create_app():
    app = Flask(__name__)
    CORS(app)

    db_url = os.getenv('DATABASE_URL')
    if not db_url:
        raise ValueError("DATABASE_URL is not set")

    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    jwt_key = os.getenv('JWT_SECRET_KEY')
    if not jwt_key:
        raise ValueError("JWT_SECRET_KEY is not set")

    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    app.config['JWT_SECRET_KEY'] = jwt_key
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

    return app


app = create_app()
db = SQLAlchemy(app)
jwt = JWTManager(app)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


class Joke(db.Model):
    __tablename__ = 'jokes'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "Bad request"}), 400
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"error": "User exists"}), 400
    new_user = User(username=data['username'], password_hash=generate_password_hash(data['password']))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "OK"}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data.get('username')).first()
    if user and check_password_hash(user.password_hash, data.get('password')):
        token = create_access_token(identity=str(user.id))
        return jsonify({"token": token, "username": user.username})
    return jsonify({"error": "Unauthorized"}), 401


@app.route('/joke/random', methods=['GET'])
def get_random_joke():
    jokes = Joke.query.all()
    if not jokes:
        return jsonify({"content": "No jokes"})
    return jsonify({"content": random.choice(jokes).content})


@app.route('/joke/add', methods=['POST'])
@jwt_required()
def add_joke():
    uid = get_jwt_identity()
    data = request.json
    last = Joke.query.filter_by(author_id=uid).order_by(Joke.created_at.desc()).first()
    if last and (datetime.utcnow() - last.created_at) < timedelta(seconds=30):
        return jsonify({"error": "Wait 30s"}), 429
    if not data or not data.get('content'):
        return jsonify({"error": "No content"}), 400
    db.session.add(Joke(content=data['content'], author_id=uid))
    db.session.commit()
    return jsonify({"message": "Created"}), 201


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)