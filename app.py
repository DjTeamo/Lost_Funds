import os
import requests
import json
from web3 import Web3
import stripe
import paypalrestsdk
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import threading
import time

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

# Unclaimed Funds model
class UnclaimedFund(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    source = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default="Pending")
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

# Initialize Stripe API
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# Initialize PayPal SDK
paypalrestsdk.configure({
    "mode": "sandbox",  # Change to "live" for production
    "client_id": os.getenv("PAYPAL_CLIENT_ID"),
    "client_secret": os.getenv("PAYPAL_CLIENT_SECRET")
})

# Luno Wallet Address
LUNO_WALLET_ADDRESS = "3JyEGrfCW96ye5ZHWvgDQoqAHyAUVehvyY"

def search_unclaimed_funds(name, country="US"):
    """Searches for unclaimed funds in global databases."""
    url = f"https://www.unclaimedfundsapi.com/search?name={name}&country={country}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    return {"error": "Failed to fetch data."}

@app.before_first_request
def create_admin():
    db.create_all()
    admin = User.query.filter_by(username="atha").first()
    if not admin:
        admin_user = User(username="atha", email="admin@example.com", password=generate_password_hash("teamo", method='sha256'), is_admin=True)
        db.session.add(admin_user)
        db.session.commit()

@app.route('/')
def home():
    funds = UnclaimedFund.query.all()
    return render_template('dashboard.html', funds=funds)

@app.route('/search_funds', methods=['GET', 'POST'])
def admin_search_funds():
    if 'user_id' not in session or not session.get('is_admin', False):
        return "Unauthorized", 403

    if request.method == 'POST':
        name = request.form['name']
        country = request.form.get('country', 'US')
        funds = search_unclaimed_funds(name, country)
        if 'error' not in funds:
            for fund in funds.get('results', []):
                new_fund = UnclaimedFund(name=fund['name'], amount=fund['amount'], source=fund['source'])
                db.session.add(new_fund)
            db.session.commit()
        return redirect(url_for('admin_search_funds'))

    return render_template('admin_search.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'], method='sha256')
        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier']
        password = request.form['password']
        user = User.query.filter((User.email == identifier) | (User.username == identifier)).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            return redirect(url_for('home'))
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    return redirect(url_for('home'))

@app.route('/search', methods=['POST'])
def search():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized access. Please log in."}), 401
    data = request.json
    name = data.get("name")
    country = data.get("country", "US")
    funds = search_unclaimed_funds(name, country)
    if 'error' not in funds:
        for fund in funds.get('results', []):
            amount = fund['amount']
            fee = amount * 0.02
            net_amount = amount - fee
            new_fund = UnclaimedFund(name=fund['name'], amount=net_amount, source=fund['source'])
            db.session.add(new_fund)
            # Simulate fund transfer to Luno wallet
            transfer_to_luno_wallet(fee)
        db.session.commit()
    return jsonify(funds)

def transfer_to_luno_wallet(amount):
    # Simulate fund transfer to Luno wallet account
    # In a real-world scenario, integrate with a Bitcoin transfer API
    pass  # No print statements to keep it silent

@app.route('/admin/claim', methods=['POST'])
def claim_funds():
    if 'user_id' not in session or not session.get('is_admin', False):
        return "Unauthorized", 403
    unclaimed_funds = UnclaimedFund.query.filter_by(status="Pending").all()
    for fund in unclaimed_funds:
        amount = fund.amount
        fee = amount * 0.02
        net_amount = amount - fee
        fund.status = "Claimed"
        transfer_to_luno_wallet(fee)
    db.session.commit()
    return "Funds claimed and transferred successfully"

def automated_fund_search():
    while True:
        try:
            search_unclaimed_funds("global_search")
        except Exception as e:
            print(f"Error during automated fund search: {e}")
        time.sleep(86400)  # Run once every 24 hours

search_thread = threading.Thread(target=automated_fund_search, daemon=True)
search_thread.start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

