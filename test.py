import requests
import time
import random
import json
from datetime import datetime
import threading
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MarketMaker:
    def __init__(self):
        self.base_url = "http://localhost:5000/api"
        self.tokens = {}  # Store tokens for multiple bot accounts
        self.currencies = ["BTC", "ETH", "USDT", "BNB", "ADA"]
        self.price_ranges = {
            "BTC": (35000, 45000),
            "ETH": (2000, 2500),
            "USDT": (0.99, 1.01),
            "BNB": (200, 300),
            "ADA": (0.4, 0.6)
        }
        self.volume_ranges = {
            "BTC": (0.1, 0.5),
            "ETH": (1, 5),
            "USDT": (100, 1000),
            "BNB": (1, 10),
            "ADA": (100, 500)
        }
        
        # Initialize bot accounts
        self.bot_accounts = [
            {"email": f"bot{i}@market.maker", "password": f"bot{i}pass"} 
            for i in range(1, 4)
        ]
        
    def setup_accounts(self):
        """Register and login bot accounts"""
        for account in self.bot_accounts:
            try:
                # Register account
                response = requests.post(
                    f"{self.base_url}/auth/register",
                    json=account
                )
                
                # Login and get token
                response = requests.post(
                    f"{self.base_url}/auth/login",
                    json=account
                )
                if response.status_code == 200:
                    self.tokens[account['email']] = response.json()['token']
                    logger.info(f"Successfully logged in {account['email']}")
                    
                    # Initial deposit for each currency
                    self.make_initial_deposit(account['email'])
                    
            except Exception as e:
                logger.error(f"Error setting up account {account['email']}: {str(e)}")

    def make_initial_deposit(self, email):
        """Make initial deposits for bot accounts"""
        headers = {'Authorization': f'Bearer {self.tokens[email]}'}
        
        for currency in self.currencies:
            deposit_amount = self.volume_ranges[currency][1] * 10  # Deposit 10x max volume
            try:
                response = requests.post(
                    f"{self.base_url}/wallet/deposit",
                    headers=headers,
                    json={
                        "currency": currency,
                        "amount": deposit_amount
                    }
                )
                if response.status_code == 200:
                    logger.info(f"Deposited {deposit_amount} {currency} for {email}")
            except Exception as e:
                logger.error(f"Error making deposit for {email}: {str(e)}")

    def create_random_order(self, currency):
        """Create a random buy or sell order"""
        try:
            # Randomly select a bot account
            email = random.choice(list(self.tokens.keys()))
            headers = {'Authorization': f'Bearer {self.tokens[email]}'}
            
            # Generate random order parameters
            order_type = random.choice(['buy', 'sell'])
            base_price = sum(self.price_ranges[currency]) / 2
            price_spread = 0.02  # 2% spread
            
            if order_type == 'buy':
                price = base_price * (1 - random.uniform(0, price_spread))
            else:
                price = base_price * (1 + random.uniform(0, price_spread))
                
            amount = random.uniform(*self.volume_ranges[currency])
            
            order_data = {
                "currency": currency,
                "amount": amount,
                "price": price,
                "type": order_type
            }
            
            response = requests.post(
                f"{self.base_url}/orderbook/create",
                headers=headers,
                json=order_data
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"Created {order_type} order: {amount} {currency} @ {price}")
            else:
                logger.warning(f"Failed to create order: {response.text}")
                
        except Exception as e:
            logger.error(f"Error creating order: {str(e)}")

    def run(self):
        """Main market making loop"""
        logger.info("Starting market maker...")
        self.setup_accounts()
        
        while True:
            try:
                # Create orders for each currency
                for currency in self.currencies:
                    # Create a buy order
                    self.create_random_order(currency)
                    time.sleep(0.2)  # Small delay between orders
                    
                    # Create a sell order
                    self.create_random_order(currency)
                    time.sleep(0.2)  # Small delay between orders
                    
                # Wait before next round
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in market maker loop: {str(e)}")
                time.sleep(5)  # Wait longer if there's an error

    def start(self):
        """Start the market maker in a separate thread"""
        thread = threading.Thread(target=self.run)
        thread.daemon = True
        thread.start()
        return thread

if __name__ == "__main__":
    market_maker = MarketMaker()
    market_maker_thread = market_maker.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down market maker...")