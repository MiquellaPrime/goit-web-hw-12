from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from starlette import status

from src.routes import auth, contacts

app = FastAPI()


@app.get("/")
async def redirect_to_docs():
    return RedirectResponse("/docs", status_code=status.HTTP_302_FOUND)


app.include_router(auth.router)
app.include_router(contacts.router)
