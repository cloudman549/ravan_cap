from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime
import uuid
import requests
import ujson

app = Flask(__name__)
CORS(app)

# ✅ Hindi/Unicode + Fast JSON config
app.config['JSON_AS_ASCII'] = False
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

# ✅ MongoDB Atlas optimized connection
client = MongoClient(
    "mongodb+srv://ravan_ext:Cloudman%40100@cluster0.cpuhyo1.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0",
    maxPoolSize=100,
    minPoolSize=5,
    serverSelectionTimeoutMS=5000,
    connectTimeoutMS=5000,
    socketTimeoutMS=10000
)

db = client["license_db"]
licenses_col = db["licenses"]
tokens_col = db["tokens"]

# ✅ MongoDB Indexing (optimized)
licenses_col.create_index("key")
tokens_col.create_index("token")
tokens_col.create_index([("license_key", 1), ("device_id", 1)])  # compound index for fast lookup
tokens_col.create_index("created_at", expireAfterSeconds=720)    # TTL index for 12 mins

# ✅ TrueCaptcha credentials
TRUECAPTCHA_USERID = "Cloudman"
TRUECAPTCHA_APIKEY = "rWYgC77DnQ259l5eDSH6"


# ✅ Fast JSON response using ujson
@app.after_request
def after_request(response):
    try:
        if response.is_json:
            response.direct_passthrough = False
            response.set_data(ujson.dumps(response.get_json(), ensure_ascii=False))
    except Exception:
        pass
    return response


@app.route('/generate-token', methods=['POST'])
def generate_token():
    data = request.get_json()
    license_key = data.get('licenseKey')
    device_id = data.get('deviceId')

    if not license_key or not device_id:
        return jsonify({"success": False, "message": "Missing licenseKey or deviceId"}), 400

    # ✅ Fetch only required fields for speed
    lic = licenses_col.find_one(
        {"key": license_key},
        {"active": 1, "paid": 1, "mac": 1}
    )

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

    # ✅ Generate token and upsert in one query
    token = str(uuid.uuid4())
    tokens_col.find_one_and_replace(
        {"license_key": license_key, "device_id": device_id},
        {
            "token": token,
            "license_key": license_key,
            "device_id": device_id,
            "created_at": datetime.utcnow(),  # TTL auto-delete
            "used": False
        },
        upsert=True
    )

    return jsonify({"success": True, "authToken": token}), 200


@app.route('/solve-truecaptcha', methods=['POST'])
def solve_truecaptcha():
    token = request.headers.get('X-Auth-Token')
    if not token:
        return jsonify({"error": "Missing auth token"}), 401

    token_doc = tokens_col.find_one(
        {"token": token},
        {"_id": 0, "token": 1}  # projection for speed
    )
    if not token_doc:
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
        response = requests.post(
            'https://api.apitruecaptcha.org/one/gettext',
            json=payload,
            timeout=8  # avoid long waits
        )
        if response.status_code != 200:
            return jsonify({'error': 'TrueCaptcha error'}), 502

        result = response.json().get('result')
        return jsonify({'result': result}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
