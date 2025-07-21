import asyncio
from flask import Flask, request, jsonify
from flask_cors import CORS
from megacloud import Megacloud

app = Flask(__name__)

CORS(app)

@app.get("/api")
def api():
    file_id = request.args.get("id")
    if not file_id:
        return jsonify({"error": "missing id"}), 400
    url = f"https://megacloud.blog/embed-2/v3/e-1/{file_id}?k=1&autoPlay=1&oa=0&asi=1"
    m = Megacloud(url)
    try:
        data = asyncio.run(m.extract())
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify(data)

if __name__ == "__main__":
    app.run(port=8446)
