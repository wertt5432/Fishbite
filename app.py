import json
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from analyzer import analyze_message, BRANDS

app = FastAPI()

MAX_BODY_BYTES = 65536


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    return response


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse("static/favicon.png")


@app.post("/api/analyze")
async def check_message_api(request: Request):
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"error": "Payload too large"})
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JSONResponse(status_code=400, content={"error": "Invalid JSON payload"})
    if not isinstance(data, dict):
        return JSONResponse(status_code=400, content={"error": "Expected a JSON object"})

    raw_text = data.get("text", "")
    text = str(raw_text if raw_text is not None else "")[:5000]
    return analyze_message(text)


@app.get("/api/brands")
def list_trusted_brands():
    return {"brands": BRANDS}


app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
def home_page():
    with open("static/index.html", "r", encoding="utf-8") as f:
        return f.read()
