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
from enum import Enum
from sqlalchemy import Enum as SqlEnum
import secrets
from flask_cors import CORS, cross_origin
from flask_migrate import Migrate
from flask import abort

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_KEY")
CORS(app, origins=["http://localhost:5173", "https://yosephghiday.github.io"], supports_credentials=True)



login_manager = LoginManager()
login_manager.init_app(app)



@login_manager.user_loader
def load_user(user_id):
    try:
        # Convert string to UUID before querying
        return User.query.get(UUID(user_id))
    except (ValueError, TypeError):
        return None  # Invalid UUID format

class MembershipTier(Enum):  # Define possible roles
    NULL = None
    GOLD = "GOLD"
    DIAMOND = "DIAMOND"
    PLATINUM = "PLATINUM"

class CustomerLevel(Enum):
    LEVEL1 = 1
    LEVEL2 = 2
    LEVEL3 = 3



class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///users.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)
migrate = Migrate(app, db)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    uid = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    fName: Mapped[str] = mapped_column(String(100), unique=True)
    lName: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    phone_number: Mapped[str] = mapped_column(String(100))
    token: Mapped[str] = mapped_column(String(100), nullable=True)

    # Use the same name as back_populates in Transaction ("transactions")
    membership_tier: Mapped[MembershipTier] = mapped_column(SqlEnum(MembershipTier),nullable=False,default=MembershipTier.NULL)
    customer_level: Mapped[CustomerLevel] = mapped_column(
        SqlEnum(CustomerLevel),  # Database enum type
        nullable=False,
        default=CustomerLevel.LEVEL1  # Default to lowest tier
    )
    balance: Mapped[float] = mapped_column(Float)
    transactions = relationship("Transaction", back_populates="user")

    def __repr__(self):
        return f"<User {self.fName} {self.lName}, Balance: {self.balance}>"

    def get_id(self):
        return str(self.uid)

with app.app_context():
    db.create_all()

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
        abort(401, description="Missing required field")
    elif user:
        # User already exists
        abort(401, description="user already exists")
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
            balance=0.0,# Explicitly set
        )
        db.session.add(new_user)
        db.session.commit()
        result = db.session.execute(db.select(User).where(User.phone_number == phonenumber))
        user = result.scalar()
        return jsonify({
            "firstName": user.fName,
            "lastName": user.lName,
            "phonenumber": user.phone_number,
            "token": user.token,
            "balance": user.balance,
            "membership": user.membership_tier.value,
            "customer_level": user.customer_level.value
        })


@app.route("/login",  methods=["POST"])
def login():
    data = request.get_json()
    phonenumber = data.get("phonenumber")
    password = data.get("password")

    result = db.session.execute(db.select(User).where(User.phone_number == phonenumber))
    user = result.scalar()
    if not user:
        abort(401, description="User not found. Please check the phone number.")


    elif not check_password_hash(user.password, password):
        abort(401, description="User not found. Please check the phone number.")

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
            "token": user.token,
            "balance": user.balance,
            "membership": user.membership_tier.value,
            "customer_level": user.customer_level.value
        })


@app.route("/getuser", methods=["POST"])
def get_user():
    data = request.get_json()
    token = data.get("token")

    result = db.session.execute(db.select(User).where(User.token == token))
    user = result.scalar()


    if user and token == str(user.token):  # Convert user.token to string for comparison
        return jsonify({
            "user_id": user.uid,
            "firstName": user.fName,
            "lastName": user.lName,
            "phonenumber": user.phone_number,
            "token": str(user.token),
            "balance": user.balance,
            "membership": user.membership_tier.value,
            "customer_level": user.customer_level.value
        })
    else:
        return jsonify({"message": "access token invalid"})


@app.route("/transaction", methods=["POST"])
def transaction():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    try:
        user_id = uuid.UUID(data.get("uid", ""))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid user ID format"}), 400

    amount = data.get("amount")
    service = data.get("service")
    payment_method = data.get("payment")

    # Check all fields
    if not all([user_id, amount, service, payment_method]):
        return jsonify({"error": "Missing required fields"}), 400

    # Get user
    user = db.session.execute(db.select(User).where(User.uid == user_id)).scalar()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Create transaction
    new_transaction = Transaction(
        amount=amount,
        paymentMethod=payment_method,
        service=service,
        user_id=user.uid
    )
    db.session.add(new_transaction)

    # Update customer level
    transaction_count = len(user.transactions) + 1
    if transaction_count >= 10:
        user.customer_level = CustomerLevel.LEVEL3
    elif transaction_count >= 5:
        user.customer_level = CustomerLevel.LEVEL2

    user.balance += 1
    db.session.commit()

    return jsonify({"message": "Transaction successfully saved"})




if __name__ == "__main__":
    app.run(debug=False, port=5001)
















