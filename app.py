from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from datetime import datetime, timezone
from mc import MC
import httpx
from typing import List

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DEFAULT_NODE = "http://localhost:8446"

nodes: List[str] = [DEFAULT_NODE]

_node_index = 0

@app.get("/nodes")
async def list_nodes():
    return {"nodes": nodes}

@app.post("/nodes")
async def add_node(url: str):
    if url not in nodes:
        nodes.append(url)
    return {"nodes": nodes}

@app.delete("/nodes")
async def remove_node(url: str):
    try:
        nodes.remove(url)
    except ValueError:
        raise HTTPException(status_code=404, detail="Node not found")
    return {"nodes": nodes}

@app.get("/distribute")
async def distribute(id: str, version: str):
    if not nodes:
        raise HTTPException(status_code=503, detail="No nodes configured")
    global _node_index
    url = nodes[_node_index % len(nodes)]
    _node_index += 1
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(connect=5.0, read=60.0, write=10.0, pool=5.0)) as client:
            resp = await client.get(f"{url}/api", params={"id": id, "version": version})
            data = resp.json()
            content = {"node": url}
            if isinstance(data, dict):
                content.update(data)
            else:
                content["response"] = data
            return JSONResponse(content=content, status_code=resp.status_code)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api")
async def api(id: str, version: str):
    url = f"https://megacloud.blog/embed-2/{version}/e-1/{id}?k=1&autoPlay=1&oa=0&asi=1"

    print(f"\n- Request ID: {id}\n- Version: {version}\n- URL: {url}\n")

    m = MC(url, version)
    try:
        data = await m.extract()
        return JSONResponse(content=data)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "mc_api",
        "nodes_count": len(nodes),
        "default_node": DEFAULT_NODE,
        "time": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/", response_class=HTMLResponse)
async def home():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>MC_API - CSC LAB</title>
        <style>
            body {
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                font-family: Arial, sans-serif;
                background-color: #333;
                text-align: center;
            }
            h1 {
                color: #f0f0f0;
            }
        </style>
    </head>
    <body>
        <h1>MC_API<br><br>CSC LAB</h1>
    </body>
    </html>
    """
    return html_content