import re
from collections import defaultdict

from app.schemas.os_info import OSInfo

# Шаблоны для анализа User-Agent
USER_AGENT_PATTERNS = {
    # Windows
    "Windows 11": [(r"Windows NT 10\.0; Win64; x64", 3.0), (r"Windows NT 10\.0", 2.0)],
    "Windows 10": [(r"Windows NT 10\.0", 3.0)],
    "Windows 8.1": [(r"Windows NT 6\.3", 3.0)],
    "Windows 8": [(r"Windows NT 6\.2", 3.0)],
    "Windows 7": [(r"Windows NT 6\.1", 3.0)],
    "Windows XP": [(r"Windows NT 5\.1", 3.0), (r"Windows XP", 2.0)],
    # macOS
    "macOS Sonoma": [(r"Mac OS X 14[_\.]", 3.0)],
    "macOS Ventura": [(r"Mac OS X 13[_\.]", 3.0)],
    "macOS Monterey": [(r"Mac OS X 12[_\.]", 3.0)],
    "macOS Big Sur": [(r"Mac OS X 11[_\.]", 3.0)],
    "macOS Catalina": [(r"Mac OS X 10_15", 3.0)],
    "macOS Mojave": [(r"Mac OS X 10_14", 3.0)],
    "macOS High Sierra": [(r"Mac OS X 10_13", 3.0)],
    "macOS Sierra": [(r"Mac OS X 10_12", 3.0)],
    # Linux
    "Ubuntu": [(r"Ubuntu", 2.0)],
    "Debian": [(r"Debian", 2.0)],
    "Fedora": [(r"Fedora", 2.0)],
    "Arch Linux": [(r"Arch Linux", 2.0)],
    "Linux": [(r"Linux", 1.5)],
    # Mobile OS
    "iOS": [(r"iPhone|iPad|iPod", 3.0), (r"iOS|iPhone OS", 3.0)],
    "Android": [(r"Android", 3.0)],
    # Browsers (для дополнительного анализа, но не ОС)
    "Chrome": [(r"Chrome/", 1.0), (r"Chromium", 1.0)],
    "Firefox": [(r"Firefox/", 1.0)],
    "Safari": [(r"Safari/", 1.0), (r"Version/\d+.*Safari/", 1.5)],
    "Edge": [(r"Edg/", 1.0)],
    "Opera": [(r"OPR/", 1.0)],
    "Internet Explorer": [(r"MSIE |Trident/", 1.0)],
    "Googlebot": [(r"Googlebot", 1.0)],
}

# Правила анализа HTTP-заголовков
HEADER_ANALYSIS_RULES = {
    "sec-ch-ua-platform": [
        (r"Windows", ("Windows", 2.0)),
        (r"macOS", ("macOS", 2.0)),
        (r"Linux", ("Linux", 2.0)),
        (r"Android", ("Android", 2.0)),
        (r"iOS", ("iOS", 2.0)),
    ],
    "user-agent": [
        (r"Windows", ("Windows", 1.0)),
        (r"Macintosh|Mac OS", ("macOS", 1.0)),
        (r"Linux", ("Linux", 1.0)),
        (r"Android", ("Android", 1.0)),
        (r"iPhone|iPad|iPod", ("iOS", 1.0)),
    ],
}

ANALYSIS_WEIGHTS = {"user_agent": 1.0, "other_headers": 0.7, "header_combinations": 0.5}


async def analyze_user_agent(user_agent: str) -> dict[str, float]:
    """
    Анализирует строку User-Agent для определения операционной системы или платформы.

    Args:
        user_agent (str): Строка User-Agent из HTTP-запроса.

    Returns:
        dict[str, float]: Словарь {ОС/платформа: баллы}
    """
    scores = defaultdict(float)
    if not user_agent:
        return scores

    user_agent = user_agent.lower()
    for os, patterns in USER_AGENT_PATTERNS.items():
        for pattern, weight in patterns:
            if re.search(pattern, user_agent, re.IGNORECASE):
                scores[os] += weight * ANALYSIS_WEIGHTS["user_agent"]
    return scores


async def analyze_other_headers(headers: dict[str, str]) -> dict[str, float]:
    """
    Анализирует дополнительные HTTP-заголовки для определения платформы.

    Args:
        headers (dict[str, str]): Словарь HTTP-заголовков.

    Returns:
        dict[str, float]: Словарь {ОС/платформа: баллы}
    """
    scores = defaultdict(float)
    for header_name, rules in HEADER_ANALYSIS_RULES.items():
        if header_name in headers:
            header_value = headers[header_name].lower()
            for pattern, (os, weight) in rules:
                if re.search(pattern, header_value, re.IGNORECASE):
                    scores[os] += weight * ANALYSIS_WEIGHTS["other_headers"]
    return scores


async def analyze_header_combinations(headers: dict[str, str]) -> dict[str, float]:
    """
    Анализирует комбинации заголовков для более точного определения ОС и браузера.

    Args:
        headers (dict[str, str]): Словарь HTTP-заголовков.

    Returns:
        dict[str, float]: Словарь {комбинация: баллы}
    """
    scores = defaultdict(float)
    user_agent = headers.get("User-Agent", "").lower()

    if "trident" in user_agent and "windows" in user_agent:
        scores["Windows (Internet Explorer)"] += (
            1.5 * ANALYSIS_WEIGHTS["header_combinations"]
        )

    if "mac" in user_agent and "safari" in user_agent and "chrome" not in user_agent:
        scores["macOS (Safari)"] += 1.2 * ANALYSIS_WEIGHTS["header_combinations"]

    if "android" in user_agent and "chrome" in user_agent:
        scores["Android (Chrome)"] += 1.0 * ANALYSIS_WEIGHTS["header_combinations"]

    return scores


async def analyze_http_headers(headers: dict[str, str]) -> dict[str, float]:
    """
    Проводит полный анализ HTTP-заголовков для оценки операционной системы и устройства.

    Args:
        headers (dict[str, str]): Словарь HTTP-заголовков.

    Returns:
        dict[str, float]: Словарь {ОС/платформа: баллы}
    """
    scores = defaultdict(float)

    user_agent_scores = await analyze_user_agent(headers.get("User-Agent", ""))
    for os, score in user_agent_scores.items():
        scores[os] += score

    other_headers_scores = await analyze_other_headers(headers)
    for os, score in other_headers_scores.items():
        scores[os] += score

    combination_scores = await analyze_header_combinations(headers)
    for os, score in combination_scores.items():
        scores[os] += score

    return scores


async def get_os_results(headers: dict[str, str]) -> OSInfo:
    """
    Возвращает наиболее вероятную ОС по итогам анализа HTTP-заголовков.

    Args:
        headers (dict[str, str]): Словарь HTTP-заголовков.

    Returns:
        OSInfo: Pydantic-модель с полем os — самой вероятной ОС.
    """
    scores = await analyze_http_headers(headers)
    top_os = (
        sorted(scores.items(), key=lambda x: x[1], reverse=True)[0][0]
        if scores
        else "Unknown"
    )
    return OSInfo(os=top_os)
