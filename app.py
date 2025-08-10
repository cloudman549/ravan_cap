from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime
import uuid
import requests

app = Flask(__name__)
CORS(app)
app.config['JSON_AS_ASCII'] = False  # हिंदी/Unicode सपोर्ट

# MongoDB Atlas connection
client = MongoClient(
    "mongodb+srv://ravan_ext:Cloudman%40100@cluster0.cpuhyo1.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
)
db = client["license_db"]
licenses_col = db["licenses"]
tokens_col = db["tokens"]

# MongoDB Indexes
licenses_col.create_index("key")
tokens_col.create_index("token")
# TTL index: tokens expire 120 सेकंड बाद (इसे अपनी जरूरत के हिसाब से सेट करें)
tokens_col.create_index("created_at", expireAfterSeconds=300)

# TrueCaptcha credentials
TRUECAPTCHA_USERID = "Cloudman"
TRUECAPTCHA_APIKEY = "rWYgC77DnQ259l5eDSH6"

@app.route('/generate-token', methods=['POST'])
def generate_token():
    try:
        data = request.get_json(force=True)
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

        # Mac address bound check
        if lic.get("mac") not in ["", device_id]:
            return jsonify({"success": False, "message": "License bound to another device"}), 403

        # अगर mac empty है तो सेट कर दो
        if lic.get("mac", "") == "":
            licenses_col.update_one({"key": license_key}, {"$set": {"mac": device_id}})

        # पुराने tokens हटाओ
        tokens_col.delete_many({"license_key": license_key, "device_id": device_id})

        # नया token बनाओ
        token = str(uuid.uuid4())
        tokens_col.insert_one({
            "token": token,
            "license_key": license_key,
            "device_id": device_id,
            "created_at": datetime.utcnow(),
            "used": False
        })

        return jsonify({"success": True, "authToken": token}), 200

    except Exception as e:
        return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500


@app.route('/solve-truecaptcha', methods=['POST'])
def solve_truecaptcha():
    try:
        token = request.headers.get('X-Auth-Token')
        if not token:
            return jsonify({"error": "Missing auth token"}), 401

        token_doc = tokens_col.find_one({"token": token})
        if not token_doc:
            return jsonify({"error": "Invalid or expired token"}), 403

        data = request.get_json(force=True)
        image_content = data.get('imageContent')
        if not image_content:
            return jsonify({"error": "Missing imageContent"}), 400

        payload = {
            'userid': TRUECAPTCHA_USERID,
            'apikey': TRUECAPTCHA_APIKEY,
            'data': image_content
        }

        # TrueCaptcha API call
        response = requests.post('https://api.apitruecaptcha.org/one/gettext', json=payload, timeout=10)
        if response.status_code != 200:
            return jsonify({'error': f'TrueCaptcha API error: {response.status_code}'}), 502

        try:
            result_json = response.json()
        except Exception:
            return jsonify({
                'error': 'TrueCaptcha से वैध JSON response नहीं मिला',
                'response_text': response.text
            }), 502

        result = result_json.get('result')
        if result is None:
            return jsonify({'error': 'TrueCaptcha response में result नहीं मिला'}), 502

        return jsonify({'result': result}), 200

    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


# ❌ Vercel या प्रोडक्शन में खुद से run न करें
# if __name__ == '__main__':
#     app.run(port=5001, debug=True)
