Megacloud Flask API

A simple Flask-based API for extracting streaming sources from Megacloud by file ID.

Requirements

- Python 3.11
- Flask
- aiohttp
- Any other dependencies required by your megacloud.py script

Installation

1. Clone this repository
   git clone <your-repo-url>
   cd <your-repo-folder>

2. Install dependencies
   It is recommended to use a virtual environment:

   python3.11 -m venv venv
   source venv/bin/activate
   pip install flask aiohttp

   If your megacloud.py requires additional dependencies, install them as well.

Usage

To run the server, simply execute:

clear && python3.11 app.py

By default, Flask will serve the API at http://127.0.0.1:5000.

API Endpoint

- GET /api?id=<file_id>

Example:

GET http://127.0.0.1:5000/api?id=2YrU0L35i6Uj

Response:
Returns a JSON with the extracted video sources and additional metadata.

Project Structure

- app.py — Main Flask server file (contains the API).
- megacloud.py — Contains the Megacloud class and decryption logic.

Example:

import asyncio
from flask import Flask, request, jsonify
from megacloud import Megacloud

app = Flask(__name__)

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
    app.run()

Notes

- The megacloud.py file must be in the same folder as app.py.
- If you want to change the port, use: app.run(port=8000)
- The endpoint only requires the id parameter (Megacloud file ID).

.gitignore

Be sure to add a .gitignore with at least:

__pycache__/
*.pyc
venv/
embed-1.min.js

Troubleshooting

- If you have issues with missing modules, make sure you installed all required packages.
- For debugging, you can add debug=True in app.run().

Questions or issues?
Open an issue or contact the maintainer.
