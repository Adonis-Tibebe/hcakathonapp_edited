from flask import Flask, request, jsonify
from sqlalchemy.dialects.postgresql import UUID
import uuid  # Use this for Postgres, optional for others
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String, Text, Float
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import os
import secrets


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_KEY")


login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    try:
        # Convert string to UUID before querying
        return User.query.get(UUID(user_id))
    except (ValueError, TypeError):
        return None  # Invalid UUID format



class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///users.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    uid = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    fName: Mapped[str] = mapped_column(String(100), unique=True)
    lName: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    phone_number: Mapped[str] = mapped_column(String(100))
    token: Mapped[str] = mapped_column(String(100), nullable=True)
    balance: Mapped[float] = mapped_column(Float)

    # Use the same name as back_populates in Transaction ("transactions")
    transactions = relationship("Transaction", back_populates="user")

    def __repr__(self):
        return f"<User {self.fName} {self.lName}, Balance: {self.balance}>"

    def get_id(self):
        return str(self.uid)


class Transaction(db.Model):
    __tablename__ = 'transactions'

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    amount: Mapped[float] = mapped_column(Float)
    paymentMethod: Mapped[str] = mapped_column(String(100))
    service: Mapped[str] = mapped_column(String(100))
    # user_id type should match User.uid type; using UUID here.
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), db.ForeignKey('users.uid'))

    # Back-populate using the same attribute name as in User ("transactions")
    user = relationship("User", back_populates="transactions")

    def __repr__(self):
        return f"<Transaction Amount: {self.amount}, User ID: {self.user_id}>"

with app.app_context():
    db.create_all()

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    fname = data.get("fname")
    lname = data.get("lname")
    phonenumber = data.get("phonenumber")
    password = data.get("password")

    result = db.session.execute(db.select(User).where(User.phone_number == phonenumber))
    user = result.scalar()
    if not fname or not lname or not phonenumber or not password:
        return jsonify({"error": "Missing required field"}), 400
    elif user:
        # User already exists
        return jsonify({"error":"user already exists"})
    else:
        hash_and_salted_password = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=8
        )
        Token = secrets.token_hex(16)
        new_user = User(
            fName=fname,
            lName=lname,
            password=hash_and_salted_password,
            phone_number=phonenumber,
            token = Token,
            balance=0.0  # Explicitly set
        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message":"signup successful!!"})


@app.route("/login",  methods=["POST"])
def login():
    data = request.get_json()
    phonenumber = data.get("phonenumber")
    password = data.get("password")

    result = db.session.execute(db.select(User).where(User.phone_number == phonenumber))
    user = result.scalar()

    if not user:
        return jsonify({"message": "account does not exist signup"})
    elif not check_password_hash(user.password, password):
        return jsonify({"message": "password is not correct"})
    else:
        login_user(user)
        Token = secrets.token_hex(16)
        current_user.token = Token
        db.session.commit()
        return jsonify({
            "user_id": user.uid,
            "firstName": user.fName,
            "lastName": user.lName,
            "phonenumber": user.phone_number,
            "token": user.token
        })


@app.route("/getuser", methods=["POST"])
def get_user():
    data = request.get_json()
    token = data.get("token")

    result = db.session.execute(db.select(User).where(User.token == token))
    user = result.scalar()


    if user and token == str(user.token):  # Convert user.token to string for comparison
            return jsonify({
                "user_id": str(user.uid),
                "firstName": user.fName,
                "lastName": user.lName,
                "phonenumber": user.phone_number,
                "token": str(user.token),# Ensure token is returned as string
                "status": "success"
            })
    else:
        return jsonify({"message": "access token invalid"})






if __name__ == "__main__":
    app.run(debug=False, port=5001)
















