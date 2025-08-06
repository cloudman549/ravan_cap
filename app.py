from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime, timedelta
import uuid
import requests
import redis

app = Flask(__name__)
CORS(app)
app.config['JSON_AS_ASCII'] = False  # Hindi/Unicode support

# ✅ MongoDB Atlas connection
client = MongoClient("mongodb+srv://ravan_ext:Cloudman%40100@cluster0.cpuhyo1.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["license_db"]
licenses_col = db["licenses"]

# ✅ Redis Upstash connection
redis_client = redis.from_url(
    "rediss://default:AVQfAAIjcDFjMDkzNTRhZTU0YTg0ZDRiOGViYTVjMjQwNTk3MmRlMnAxMA@integral-parakeet-21535.upstash.io:6379",
    decode_responses=True
)

# ✅ TrueCaptcha credentials
TRUECAPTCHA_USERID = "Cloudman"
TRUECAPTCHA_APIKEY = "rWYgC77DnQ259l5eDSH6"

@app.route('/generate-token', methods=['POST'])
def generate_token():
    data = request.get_json()
    license_key = data.get('licenseKey')
    device_id = data.get('deviceId')

    if not license_key or not device_id:
        return jsonify({"success": False, "message": "Missing licenseKey or deviceId"}), 400

    lic = licenses_col.find_one({"key": license_key})
    if not lic:
        return jsonify({"success": False, "message": "License key not found"}), 404
    if not lic.get("active", False):
        return jsonify({"success": False, "message": "License is deactivated"}), 403
    if not lic.get("paid", False):
        return jsonify({"success": False, "message": "License is unpaid"}), 403

    if lic.get("mac") not in ["", device_id]:
        return jsonify({"success": False, "message": "License bound to another device"}), 403

    if lic.get("mac", "") == "":
        licenses_col.update_one({"key": license_key}, {"$set": {"mac": device_id}})

    token = str(uuid.uuid4())
    redis_client.setex(f"token:{token}", timedelta(minutes=10), device_id)

    return jsonify({"success": True, "authToken": token}), 200

@app.route('/solve-truecaptcha', methods=['POST'])
def solve_truecaptcha():
    token = request.headers.get('X-Auth-Token')
    if not token:
        return jsonify({"error": "Missing auth token"}), 401

    device_id = redis_client.get(f"token:{token}")
    if not device_id:
        return jsonify({"error": "Invalid or expired token"}), 403

    data = request.get_json()
    image_content = data.get('imageContent')
    if not image_content:
        return jsonify({"error": "Missing imageContent"}), 400

    payload = {
        'userid': TRUECAPTCHA_USERID,
        'apikey': TRUECAPTCHA_APIKEY,
        'data': image_content
    }

    try:
        response = requests.post('https://api.apitruecaptcha.org/one/gettext', json=payload)
        if response.status_code != 200:
            return jsonify({'error': 'TrueCaptcha error'}), 502

        result = response.json().get('result')
        return jsonify({'result': result}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
