"""
내부 네트워크(LAN) ARP 스캐너 모듈
같은 공유기(내부망)에 연결되어 켜져 있는 기기들의 IP, MAC 주소, 호스트 이름을 빠르게 탐색합니다.
Windows에서는 SendARP Win32 API를 병렬 호출하여 방화벽(ICMP 차단)과 무관하게 정확한 MAC 주소를 수집합니다.
"""

import ctypes
import os
import re
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple


def _is_valid_unicast_mac(mac: str) -> bool:
    """브로드캐스트 및 멀티캐스트 MAC 주소를 제외합니다."""
    clean = mac.replace(":", "").replace("-", "").upper()
    if len(clean) != 12:
        return False
    if clean in ("000000000000", "FFFFFFFFFFFF"):
        return False
    try:
        first_byte = int(clean[:2], 16)
        # 최하위 비트가 1이면 멀티캐스트/브로드캐스트 주소
        if first_byte & 1:
            return False
    except ValueError:
        return False
    return True


def normalize_mac(mac: str) -> str:
    """MAC 주소를 대문자 콜론 형식(AA:BB:CC:DD:EE:FF)으로 통일합니다."""
    clean = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(clean) != 12:
        return mac.strip().upper()
    return ":".join(clean[i : i + 2] for i in range(0, 12, 2))


def get_primary_local_ip() -> Optional[str]:
    """기본 게이트웨이로 향하는 주 로컬 IPv4 주소를 가져옵니다."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1.0)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            if not ip.startswith("127."):
                return ip
        except Exception:
            pass
    return None


def _send_arp_windows(ip: str) -> Optional[Tuple[str, str]]:
    """Windows iphlpapi.SendARP를 호출해 특정 IP의 MAC 주소를 조회합니다."""
    try:
        iphlpapi = ctypes.windll.iphlpapi
        dest_ip = struct.unpack("<I", socket.inet_aton(ip))[0]
        mac_buf = (ctypes.c_ubyte * 6)()
        mac_len = ctypes.c_ulong(6)
        res = iphlpapi.SendARP(dest_ip, 0, ctypes.byref(mac_buf), ctypes.byref(mac_len))
        if res == 0 and mac_len.value == 6:
            mac = ":".join(f"{b:02X}" for b in mac_buf[:6])
            if _is_valid_unicast_mac(mac):
                return ip, mac
    except Exception:
        pass
    return None


def _resolve_hostname(ip: str) -> str:
    """IP 주소로부터 역방향 DNS/로컬 호스트 이름을 조회합니다."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        if name and name != ip:
            return name.split(".")[0]
    except Exception:
        pass
    return ""


def _read_arp_table() -> Dict[str, str]:
    """OS의 현재 ARP 캐시 테이블(arp -a)을 읽어 {ip: mac} 딕셔너리를 반환합니다."""
    found: Dict[str, str] = {}
    try:
        startupinfo = None
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        output = subprocess.check_output(
            ["arp", "-a"],
            stderr=subprocess.DEVNULL,
            startupinfo=startupinfo,
            timeout=5,
        )
        text = output.decode("cp949", errors="ignore")
        pattern = re.compile(
            r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})"
        )
        for ip, raw_mac in pattern.findall(text):
            mac = normalize_mac(raw_mac)
            if _is_valid_unicast_mac(mac):
                found[ip] = mac
    except Exception:
        pass
    return found


def scan_lan_arp(subnet_prefix: Optional[str] = None, resolve_names: bool = True) -> Tuple[bool, List[Dict[str, str]], str]:
    """
    내부망(/24 대역)을 ARP 스캔하여 살아있는 기기 목록을 반환합니다.
    반환 형식: (성공여부, [{'name': str, 'mac': str, 'ip': str, 'source': 'ARP스캔'}], 메시지)
    """
    local_ip = get_primary_local_ip()
    if not subnet_prefix:
        if not local_ip:
            return False, [], "로컬 네트워크 IP 주소를 찾을 수 없습니다."
        subnet_prefix = ".".join(local_ip.split(".")[:3])

    target_ips = [f"{subnet_prefix}.{i}" for i in range(1, 255)]
    ip_to_mac: Dict[str, str] = {}

    if os.name == "nt":
        # Windows: SendARP 254개 병렬 호출 (~3초 소요)
        with ThreadPoolExecutor(max_workers=254) as executor:
            for result in executor.map(_send_arp_windows, target_ips):
                if result:
                    ip, mac = result
                    ip_to_mac[ip] = mac
    else:
        # 비-Windows 환경 fallback: ping sweep 후 arp -a 읽기
        def _ping(ip: str):
            subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        with ThreadPoolExecutor(max_workers=64) as executor:
            list(executor.map(_ping, target_ips))

    # 기존 ARP 캐시 병합 (같은 대역 우선)
    for ip, mac in _read_arp_table().items():
        if ip not in ip_to_mac and ip.startswith(subnet_prefix + "."):
            ip_to_mac[ip] = mac

    if not ip_to_mac:
        return True, [], f"{subnet_prefix}.0/24 대역에서 응답한 기기가 없습니다."

    # 호스트 이름 병렬 조회 (데몬 스레드로 최대 1.5초 대기 후 즉시 반환)
    ip_to_name: Dict[str, str] = {}
    if resolve_names and ip_to_mac:
        lock = threading.Lock()

        def _worker(target_ip: str):
            resolved = _resolve_hostname(target_ip)
            if resolved:
                with lock:
                    ip_to_name[target_ip] = resolved

        threads = []
        for ip in ip_to_mac:
            t = threading.Thread(target=_worker, args=(ip,), daemon=True)
            t.start()
            threads.append(t)

        deadline = time.monotonic() + 1.5
        for t in threads:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            t.join(timeout=remaining)

    # IP 마지막 옥텟 기준 정렬
    sorted_ips = sorted(ip_to_mac.keys(), key=lambda x: tuple(int(p) for p in x.split(".")))
    devices: List[Dict[str, str]] = []
    for ip in sorted_ips:
        mac = ip_to_mac[ip]
        hostname = ip_to_name.get(ip, "")
        if ip == local_ip and not hostname:
            hostname = socket.gethostname()
        display_name = hostname if hostname else f"기기 ({ip})"
        if ip == local_ip:
            display_name = f"{display_name} [현재 PC]"

        devices.append({
            "name": display_name,
            "mac": mac,
            "ip": ip,
            "source": "ARP스캔",
        })

    return True, devices, f"{subnet_prefix}.0/24 대역 ARP 스캔 완료: {len(devices)}대 발견"


if __name__ == "__main__":
    ok, devs, msg = scan_lan_arp()
    print(msg)
    for d in devs:
        print(f" - {d['ip']:15s} | {d['mac']} | {d['name']}")
