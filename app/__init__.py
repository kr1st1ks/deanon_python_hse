from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.routers.analyze import router as analyze_router
from app.api.routers.analyze_quick import router as analyze_quick_router
from app.api.routers.dnsleak import router as dnsleak_router
from app.api.routers.root import router as root_router

app = FastAPI(title="Deanon Service")

templates = Jinja2Templates(directory="app/templates")

app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(root_router, prefix="")
app.include_router(analyze_router, prefix="")
app.include_router(analyze_quick_router, prefix="")
app.include_router(dnsleak_router, prefix="")
