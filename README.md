Megacloud Flask API

A simple Flask-based API for extracting streaming sources from Megacloud by file ID.

Requirements

- Python 3.11
- Flask
- aiohttp
- flask-cors

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

By default, Flask will serve the API at http://127.0.0.1:8446.

API Endpoint

- GET /api?id=<file_id>

Example:

GET http://127.0.0.1:8446/api?id=2YrU0L35i6Uj

Response:
Returns a JSON with the extracted video sources and additional metadata.

Project Structure

- app.py — Main Flask server file (contains the API).
- megacloud.py — Contains the Megacloud class and decryption logic.
