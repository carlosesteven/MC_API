# MC API

A MC API for extracting streaming sources from MC by file ID.

## Requirements

- Python 3.11

- aiohttp
- fastapi
- uvicorn
- httpx

## Installation

1. Clone this repository

       git clone https://github.com/carlosesteven/MC_API.git

       cd MC_API

3. Install dependencies

       pip install fastapi uvicorn aiohttp httpx

## Usage

To run the server, simply execute:

    clear && python -m uvicorn app:app --host 0.0.0.0 --port 8446

By default, Server will the API at http://127.0.0.1:8446.
The node list starts with this local address so distribution works without extra configuration.

## API Endpoints

    GET /api?id=<file_id>&version=<version>
    GET /distribute?id=<file_id>&version=<version>
    GET /nodes
    POST /nodes?url=<node_url>
    DELETE /nodes?url=<node_url>

## Examples:

    GET http://127.0.0.1:8446/api?id=XXXXXX&version=XX
    GET http://127.0.0.1:8446/distribute?id=XXXXXX&version=XX

## Response:

    Returns a JSON with the extracted video sources and additional metadata.
    `/distribute` responses also include the node address that processed the request.

# Running the Project with Python 3.11

1. Create a virtual environment with Python 3.11:

       python3.11 -m venv venv

2. Activate the virtual environment:

       source venv/bin/activate

3. Install the project dependencies:

       pip install fastapi uvicorn aiohttp httpx

4. Run the project:

       python -m uvicorn app:app --host 0.0.0.0 --port 8446

5. Deactivate the virtual environment (optional):

       deactivate

# Running Flask Server in Background (Linux)

To run your Flask server in the background and keep it running after closing the terminal, use the following commands:

1. Start the Server in Background

       nohup python -m uvicorn app:app --host 0.0.0.0 --port 8446 > /dev/null 2>&1 &

   This command will start the server in the background.

2. Check if the Server is Running

       ps aux | grep uvicorn

   This will show you the process ID (PID) of the running app.py server.

4. Stop the Server

       kill pid

   OR

       pkill -f "uvicorn app:app"

   This command will stop all running processes that match app.py.
