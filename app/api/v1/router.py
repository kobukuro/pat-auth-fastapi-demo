from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.api.v1.tokens import router as tokens_router
from app.api.v1.users import router as users_router
from app.api.v1.workspaces import router as workspaces_router
from app.api.v1.fcs import router as fcs_router

router = APIRouter()
router.include_router(auth_router)
router.include_router(tokens_router)
router.include_router(workspaces_router)
router.include_router(users_router)
router.include_router(fcs_router)
