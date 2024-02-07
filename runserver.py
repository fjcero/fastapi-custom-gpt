import uvicorn

def start():
    uvicorn.run("server.main:app", host="127.0.0.1", port=8000, reload=True, workers=2)
