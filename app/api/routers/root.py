from fastapi import APIRouter
from fastapi.responses import RedirectResponse

router = APIRouter()


@router.get("/", include_in_schema=False)
async def root():
    """
    Перенаправляет пользователя на эндпоинт /analyze.

    Returns:
        RedirectResponse: Ответ с перенаправлением на /analyze.
    """
    return RedirectResponse(url="/analyze")
