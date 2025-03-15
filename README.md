# Flask Application for Unclaimed Funds and Crypto Wallets

This application allows users to search for unclaimed funds and check for dormant cryptocurrency wallets. It also provides user authentication and the ability to transfer funds to an admin payout account.

## Features
- User Registration and Login (using username or email)
- Search for unclaimed funds
- Check dormant cryptocurrency wallets
- Transfer funds to admin payout account
- User authentication
- Admin functionalities for withdrawing funds and searching for unclaimed funds
- Automated daily search for unclaimed funds

## Requirements
- Python 3.x
- Flask
- Flask SQLAlchemy
- Requests
- Web3.py
- Werkzeug
- Stripe API
- PayPal SDK

## Setup
1. Clone the repository.
2. Install the required packages:
    ```bash
    pip install -r requirements.txt
    ```
3. Set up the environment variables:
    ```bash
    export SECRET_KEY="your_secret_key"
    export STRIPE_SECRET_KEY="your_stripe_secret_key"
    export PAYPAL_CLIENT_ID="your_paypal_client_id"
    export PAYPAL_CLIENT_SECRET="your_paypal_client_secret"
    ```
4. Run the application:
    ```bash
    python app.py
    ```

## Endpoints
- `/` - Home page
- `/register` - User registration
- `/login` - User login (using email or username)
- `/logout` - User logout
- `/search` - Search for unclaimed funds
- `/admin/withdraw` - Admin endpoint to withdraw funds
- `/search_funds` - Admin endpoint to search for unclaimed funds

## Usage
1. Register and log in as a user.
2. Use the search endpoint to look for unclaimed funds.
3. Use the admin endpoints to withdraw funds and search for unclaimed funds.

## License
This project is licensed under the MIT License.
