from fastapi import APIRouter, HTTPException, Query

from app.schemas.dns_info import DnsLeakResult, DnsLeakTest
from app.services.dns_service import analyze_dns_leak, generate_dns_leak_test

router = APIRouter(prefix="/dnsleak", tags=["DNSLeak"])


@router.post("/start", response_model=DnsLeakTest)
async def dnsleak_start():
    """
    Генерирует тестовые поддомены для DNS-leak теста и test_id.

    Returns:
        DnsLeakTest: Сгенерированные поддомены и test_id.
    """
    leak_test = generate_dns_leak_test(count=3, base_domain="example.com")
    return leak_test


@router.get("/check", response_model=DnsLeakResult)
async def dnsleak_check(
    test_id: str = Query(..., description="ID ранее сгенерированного DNS-leak теста"),
):
    """
    Анализирует, были ли резолвлены клиентом все тестовые поддомены (DNS-leak check).

    Args:
        test_id (str): ID DNS-leak теста.

    Returns:
        DnsLeakResult: Результаты теста.
    """
    try:
        result = await analyze_dns_leak(test_id=test_id, wait_time=0)
        return result
    except ValueError:
        raise HTTPException(status_code=404, detail="Ошибка. Такого значения нет")
