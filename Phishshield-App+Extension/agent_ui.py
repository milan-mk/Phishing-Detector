import threading
from flask import Flask, request, jsonify
import tldextract
import pystray
from pystray import MenuItem as item
from PIL import Image, ImageDraw
import requests
from win10toast import ToastNotifier
from dotenv import load_dotenv
import os

load_dotenv()

# --- Flask app ---
app = Flask(__name__)
toaster = ToastNotifier()

@app.route("/check", methods=["POST"])
def check_url():
    data = request.get_json()
    url = data.get("url")
    ext = tldextract.extract(url)
    domain = ".".join([ext.domain, ext.suffix])

    # Simple check
    #check
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "accept": "application/json",
        "x-apikey": os.getenv("API_KEY"),
        "content-Type": "application/x-www-form-urlencoded"
    }
    payload = {"url": f"https://{domain}"}

    response = requests.post(api_url, data=payload, headers=headers)
    id_url = response.json()["data"]["links"]["self"]

    #recieve analysis
    headers = {
        "accept": "application/json",
        "x-apikey": os.getenv("API_KEY")
    }
    analyse = requests.get(id_url, headers = headers)

    is_phish = analyse.json()["data"]["attributes"]["stats"]["malicious"] >= 1

    # 🔔 Show notification
    if(is_phish):
        toaster.show_toast(
            "PhishShied",
            f"Checked: {domain}\nResult: {'Phishing ⚠️'}",
            duration=3,
            threaded=True
            )

    print(f"Checking: {url} -> {domain} | {'Phish' if is_phish else 'Safe'}")
    return jsonify({"phishing": is_phish})

def run_flask():
    app.run(port=5000, debug=False, use_reloader=False)

# --- Tray app ---
def create_image():
    image = Image.new("RGB", (64, 64), "blue")
    draw = ImageDraw.Draw(image)
    draw.rectangle((16, 16, 48, 48), fill="white")
    return image

def quit_app(icon, item):
    icon.stop()
    return 0 

def show_status(icon, item):
    print("Tray clicked!")
    return 0  # always return int

if __name__ == "__main__":
    # Start Flask in a background thread
    threading.Thread(target=run_flask, daemon=True).start()

    # Start tray icon (blocking)
    icon = pystray.Icon("PhishGuard", create_image(),
                        menu=pystray.Menu(item('Quit', quit_app)))
    icon.run()
