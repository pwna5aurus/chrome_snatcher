#http://localhost:9222/json/version
#chrome --headless=new --remote-debugging-port=9222 --remote-allow-origins="*" --no-sandbox --disable-gpu --profile-directory="Profile <x>" (In my case it was 7, might have to do some additional trial/error here)

import asyncio
import websockets
import json
import requests
import subprocess
import pychrome
import time

p_num = 0

chrome_command = [
    "chrome",
    "--remote-debugging-port=9222",
    "--remote-allow-origins=*",
    "--no-sandbox",
    "--disable-gpu",
    f"--profile-directory=Profile {p_num}"
]

subprocess.run(chrome_command)

def get_cookies_from_gmail(browser):
    """Function to browse to Gmail and get cookies."""
    tab = browser.new_tab()
    
    # Define the event handlers.
    def _load_listener(**kwargs):
        # Domains we're interested in.
        domains = ["mail.google.com", "contacts.google.com", "ogs.google.com"]

        # Cookies we're interested in.
        cookies_of_interest = [
            "__Secure-3PSIDCC",
            "__Secure-1PSID",
            "SID",
            "__Secure-3PSIDTS",
            "__Secure-1PSIDTS",
            "__Secure-1PSIDCC",
            "SIDCC",
            "__Secure-3PAPISID",
            "HSID",
            "__Secure-1PAPISID",
            "__Secure-3PSID",
            "SAPISID",
            "APISID",
            "SSID",
        ]

        for domain in domains:
            cookies = tab.Network.getCookies(urls=[f"https://{domain}"])
            for cookie in cookies['cookies']:
                if cookie['name'] in cookies_of_interest:
                    print(f"Domain: {domain}, Name: {cookie['name']}, Value: {cookie['value']}")

    tab.set_listener("Network.loadingFinished", _load_listener)

    tab.start()
    tab.Network.enable()

    # Navigate to Gmail.
    tab.Page.navigate(url="https://mail.google.com/mail/u/0/#inbox")

    # Wait for a while to ensure cookies are loaded and all related requests are finished.
    time.sleep(10)

    # Cleanup.
    tab.stop()
    browser.close_tab(tab)

if __name__ == "__main__":
    browser = pychrome.Browser(url="http://127.0.0.1:9222")
    get_cookies_from_gmail(browser)
