from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from megacloud import Megacloud

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api")
async def api(id: str, version: str):
    url = f"https://megacloud.blog/embed-2/{version}/e-1/{id}?k=1&autoPlay=1&oa=0&asi=1"
    m = Megacloud(url)
    try:
        data = await m.extract()
        return JSONResponse(content=data)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)