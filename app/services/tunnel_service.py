import asyncio
import socket
import time
from typing import Optional

from scapy.all import Raw, sniff, sr1
from scapy.layers.inet import GRE, ICMP, IP, TCP, UDP
from scapy.layers.ipsec import AH, ESP
from scapy.layers.l2 import Ether
from scapy.layers.vxlan import VXLAN

from app.schemas.tunnel_ping import PingInfo, PingResponse, TunnelInfo


def detect_tunnel(pkt) -> Optional[TunnelInfo]:
    """
    Детектирует наличие сетевого туннеля в переданном пакете.

    Args:
        pkt: Scapy-пакет для анализа

    Returns:
        TunnelInfo: Pydantic-модель с типом туннеля и ключевыми IP-адресами,
        либо None если туннелирование не обнаружено.
    """
    if IP not in pkt:
        return None

    ip_layer = pkt[IP]

    if GRE in pkt:
        inner = pkt[GRE].payload
        if IP in inner:
            inner_ip = inner[IP]
            return TunnelInfo(
                tunnel_type="GRE",
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                inner_src=inner_ip.src,
                inner_dst=inner_ip.dst,  # исправлено
            )
    elif UDP in pkt and pkt[UDP].dport == 4789 and VXLAN in pkt:
        inner = pkt[VXLAN].payload
        if IP in inner:
            inner_ip = inner[IP]
            return TunnelInfo(
                tunnel_type="VXLAN",
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                inner_src=inner_ip.src,
                inner_dst=inner_ip.dst,
            )
    elif isinstance(ip_layer.payload, IP):
        inner_ip = ip_layer.payload
        return TunnelInfo(
            tunnel_type="IP-in-IP",
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            inner_src=inner_ip.src,
            inner_dst=inner_ip.dst,
        )
    elif UDP in pkt and pkt[UDP].dport == 1701:
        return TunnelInfo(
            tunnel_type="L2TP",
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            inner_src="N/A (L2TP payload)",
            inner_dst="N/A (L2TP payload)",
        )
    elif (UDP in pkt and pkt[UDP].dport in [1194, 53, 443]) or (
        TCP in pkt and pkt[TCP].dport in [1194, 53, 443]
    ):
        if Raw in pkt:
            raw_data = bytes(pkt[Raw])
            if raw_data.startswith(b"OpenVPN"):
                return TunnelInfo(
                    tunnel_type="OpenVPN",
                    src_ip=ip_layer.src,
                    dst_ip=ip_layer.dst,
                    inner_src="N/A (encrypted)",
                    inner_dst="N/A (encrypted)",
                )
            elif raw_data.startswith(b"\x16\x03"):
                return TunnelInfo(
                    tunnel_type="OpenVPN (TLS)",
                    src_ip=ip_layer.src,
                    dst_ip=ip_layer.dst,
                    inner_src="N/A (encrypted)",
                    inner_dst="N/A (encrypted)",
                )
    elif Ether in pkt and pkt[Ether].type == 0x8847:
        return TunnelInfo(
            tunnel_type="MPLS",
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            inner_src="N/A (Label-based)",
            inner_dst="N/A (Label-based)",
        )
    elif ESP in pkt or AH in pkt:
        return TunnelInfo(
            tunnel_type="IPsec",
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            inner_src="N/A (encrypted)",
            inner_dst="N/A (encrypted)",
        )

    return None


async def check_ip_for_tunnel(
    target_ip: str,
    interface: str = "Беспроводная сеть",
    timeout: int = 5,
    max_packets: int = 10,
) -> Optional[TunnelInfo]:
    """
    Проверяет, проходит ли сетевой трафик по указанному IP через туннель
    по выбранному интерфейсу.

    Args:
        target_ip (str): IP-адрес для проверки.
        interface (str): Имя сетевого интерфейса.
        timeout (int): Максимальное время ожидания, сек.
        max_packets (int): Максимальное количество анализируемых пакетов.

    Returns:
        TunnelInfo | None: Информация о найденном туннеле или None, если не найден.
    """
    loop = asyncio.get_event_loop()
    queue = asyncio.Queue()

    def packet_handler(pkt):
        if IP in pkt:
            ip = pkt[IP]
            if ip.src == target_ip or ip.dst == target_ip:
                tunnel_info = detect_tunnel(pkt)
                if tunnel_info:
                    queue.put_nowait(tunnel_info)

    async def start_sniffing():
        await loop.run_in_executor(
            None,
            lambda: sniff(
                iface=interface,
                prn=packet_handler,
                filter=f"host {target_ip}",
                store=0,
                count=max_packets,
                timeout=timeout,
            ),
        )

    try:
        await asyncio.create_task(start_sniffing())
    except Exception:
        return None

    try:
        tunnel_info = await asyncio.wait_for(queue.get(), timeout=timeout)
        return tunnel_info if tunnel_info else None
    except asyncio.TimeoutError:
        return None


def sync_double_ping(host: str) -> Optional[PingResponse]:
    """
    Выполняет двойной ICMP-ping до узла и сравнивает результаты (TTL, задержку).

    Args:
        host (str): Имя хоста или IP-адрес.

    Returns:
        PingResponse: Pydantic-модель с результатом теста.
            - result=True, info=строка: есть подозрение на туннель
            - result=False, info="All OK": все нормально
            - info=None: нет ответа хотя бы от одного пинга
    """
    try:
        target_ip = socket.gethostbyname(host)
    except socket.gaierror:
        return PingResponse(result=False, info=None)
    try:
        pkt1 = IP(dst=target_ip) / ICMP(seq=1)
        pkt2 = IP(dst=target_ip) / ICMP(seq=2)

        responses = []
        for i, pkt in enumerate([pkt1, pkt2]):
            start_time = time.time()
            response = sr1(pkt, verbose=0, timeout=2)
            end_time = time.time()
            if response:
                responses.append(
                    PingInfo(
                        seq=i + 1,
                        src_ip=response.src,
                        dst_ip=target_ip,
                        rtt=(end_time - start_time) * 1000,
                        ttl=response.ttl,
                    )
                )
            else:
                return PingResponse(
                    result=True,
                    info=None,
                )

        if len(responses) < 2:
            return PingResponse(
                result=True,
                info=None,
            )
        ping1, ping2 = responses

        if ping1.ttl != ping2.ttl:
            return PingResponse(
                result=True,
                info="Different TTL",
            )
        if abs(ping1.rtt - ping2.rtt) > 50:
            return PingResponse(
                result=True,
                info="Too big time difference",
            )
        return PingResponse(
            result=False,
            info="All OK",
        )
    except Exception:
        return PingResponse(result=False, info=None)


async def get_double_ping(host: str) -> Optional[PingResponse]:
    """
    Асинхронная обёртка для sync_double_ping.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: sync_double_ping(host))
