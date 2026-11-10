from fastapi import APIRouter

from app.api.v1 import auth, dashboard, scan, system

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(system.router)
api_router.include_router(auth.router)
api_router.include_router(scan.router)
api_router.include_router(dashboard.router)

