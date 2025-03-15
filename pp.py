import os
import requests
import json
from web3 import Web3
import stripe
import paypalrestsdk
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

# Initialize Stripe API
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# Initialize PayPal SDK
paypalrestsdk.configure({
    "mode": "sandbox",  # Change to "live" for production
    "client_id": os.getenv("PAYPAL_CLIENT_ID"),
    "client_secret": os.getenv("PAYPAL_CLIENT_SECRET")
})

def search_unclaimed_funds(name, country="US"):
    """Searches for unclaimed funds in global databases."""
    url = f"https://www.unclaimedfundsapi.com/search?name={name}&country={country}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    return {"error": "Failed to fetch data."}

def check_dormant_crypto_wallets(wallet_address):
    """Checks blockchain for idle cryptocurrency wallets."""
    INFURA_URL = "https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID"
    web3 = Web3(Web3.HTTPProvider(INFURA_URL))
    balance = web3.eth.get_balance(wallet_address)
    if balance > 0:
        return {"wallet": wallet_address, "balance": web3.from_wei(balance, 'ether')}
    return {"wallet": wallet_address, "message": "No funds found."}

def charge_commission(user_email, amount):
    """Charges a commission using PayPal or Stripe."""
    try:
        stripe.PaymentIntent.create(
            amount=int(amount * 100),  # Convert to cents
            currency="usd",
            payment_method_types=["card"],
            receipt_email=user_email,
        )
        return "Stripe payment successful."
    except stripe.error.StripeError as e:
        return f"Stripe payment failed: {str(e)}"
    except Exception as e:
        return f"Stripe payment error: {str(e)}"

    try:
        payment = paypalrestsdk.Payment({
            "intent": "sale",
            "payer": {"payment_method": "paypal"},
            "transactions": [{
                "amount": {"total": str(amount), "currency": "USD"},
                "description": "Unclaimed funds recovery service fee."
            }],
            "redirect_urls": {
                "return_url": "https://yourwebsite.com/payment-success",
                "cancel_url": "https://yourwebsite.com/payment-cancel"
            }
        })
        if payment.create():
            return "PayPal payment created successfully."
        else:
            return f"PayPal payment failed: {payment.error}"
    except paypalrestsdk.exceptions.PayPalError as e:
        return f"PayPal payment error: {str(e)}"
    except Exception as e:
        return f"PayPal payment error: {str(e)}"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'], method='sha256')
        new_user = User(email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('home'))
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('home'))

@app.route('/search', methods=['POST'])
def search():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized access. Please log in."}), 401

    data = request.json
    name = data.get("name")
    country = data.get("country", "US")
    funds = search_unclaimed_funds(name, country)
    return jsonify(funds)

@app.route('/charge', methods=['POST'])
def charge():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized access. Please log in."}), 401

    data = request.json
    user_email = data.get("email")
    amount = float(data.get("amount"))
    payment_result = charge_commission(user_email, amount)
    return jsonify({"status": payment_result})

if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
