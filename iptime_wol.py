"""
ipTIME 공유기 WOL(Wake-on-LAN) 제어 모듈
기능:
1. ipTIME 관리자 웹 세션 로그인 (보안 헤더 및 세션 쿠키 처리)
2. 공유기에 등록된 WOL 대상 기기 목록 조회
3. 공유기의 DHCP 할당 현황, 내부망/접속 기기(무선/트래픽) 목록 긁어오기
4. 미등록 기기를 공유기 WOL 목록에 자동 등록(act=add)
5. 특정 MAC 주소로 WOL 매직 패킷 송출 요청
"""

import re
import requests
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urljoin


MAC_REGEX = re.compile(r'([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})')
IP_REGEX = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})\b')

UI_NOISE_WORDS = {
    "동적", "고정", "수동", "자동", "연결", "연결됨", "해제", "삭제", "추가",
    "적용", "취소", "저장", "수정", "선택", "pc 켜기", "켜기", "wol", "dhcp",
    "static", "dynamic", "manual", "auto", "connected", "delete", "add",
    "wake", "mac", "ip", "사용", "사용함", "사용안함", "허용", "차단",
}


def _normalize_mac(mac: str) -> str:
    clean = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(clean) != 12:
        return mac.strip().upper()
    return ":".join(clean[i : i + 2] for i in range(0, 12, 2))


def _is_valid_unicast_mac(mac: str) -> bool:
    clean = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(clean) != 12:
        return False
    if clean in ("000000000000", "FFFFFFFFFFFF"):
        return False
    try:
        if int(clean[:2], 16) & 1:
            return False
    except ValueError:
        return False
    return True


def _is_valid_client_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    if any(n < 0 or n > 255 for n in nums):
        return False
    if ip in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
        return False
    if nums[0] >= 224 or nums[0] == 255:
        return False
    return True


def _pick_device_name(candidates: List[str], fallback_ip: str = "") -> str:
    """테이블 셀 텍스트 후보들 중 실제 기기/호스트 이름에 가장 적합한 값을 고릅니다."""
    for raw in candidates:
        val = raw.strip().strip("'\"")
        if not val:
            continue
        if MAC_REGEX.fullmatch(val) or IP_REGEX.fullmatch(val):
            continue
        # 순번(숫자만) 또는 시간(01:23:45) 또는 UI 버튼 문구 제외
        if val.isdigit():
            continue
        if re.fullmatch(r'\d+:\d{2}(:\d{2})?', val):
            continue
        if re.fullmatch(r'[\d\s일시간분초hms:-]+', val, re.IGNORECASE):
            continue
        if val.lower() in UI_NOISE_WORDS:
            continue
        return val
    return f"기기 ({fallback_ip})" if fallback_ip else "알 수 없는 기기"


class IpTimeWOL:
    def __init__(self, host: str = "192.168.0.1", port: int = 80, ssl: bool = False, timeout: int = 10):
        clean_host = host.replace("http://", "").replace("https://", "").split(":")[0]
        self.host = clean_host
        self.port = port
        self.scheme = "https" if ssl else "http"
        self.base_url = f"{self.scheme}://{self.host}:{self.port}"
        self.timeout = timeout
        self.cgi_dir = "sess-bin"  # 신형: sess-bin, 구형: cgi-bin

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Host": f"{self.host}:{self.port}",
        })
        self.is_logged_in = False

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        """
        ipTIME 관리자 페이지에 로그인하여 세션 쿠키(efm_session_id)를 획득합니다.
        펌웨어 버전에 따른 경로(/sess-bin/ 및 구형 /cgi-bin/)를 자동 감지합니다.
        """
        login_session_url = f"{self.base_url}/sess-bin/login_session.cgi"
        login_handler_url = f"{self.base_url}/sess-bin/login_handler.cgi"

        try:
            self.session.headers.update({"Referer": f"{self.base_url}/login/login.cgi"})
            init_res = self.session.get(login_session_url, timeout=self.timeout)

            if init_res.status_code == 404:
                self.cgi_dir = "cgi-bin"
                login_session_url = f"{self.base_url}/login/login.cgi"
                login_handler_url = f"{self.base_url}/cgi-bin/login_handler.cgi"
                init_res = self.session.get(login_session_url, timeout=self.timeout)

            post_data = {
                "init_status": "1",
                "captcha_on": "0",
                "captcha_file": "",
                "username": username,
                "passwd": password,
                "default_passwd": "초기암호:admin(변경필요)",
                "captcha_code": ""
            }
            self.session.headers.update({"Referer": login_session_url})

            res = self.session.post(login_handler_url, data=post_data, timeout=self.timeout)
            res_text = res.text

            session_id = None
            if "efm_session_id" in self.session.cookies:
                session_id = self.session.cookies["efm_session_id"]
            else:
                match = re.search(r"setCookie\(\s*['\"]efm_session_id['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)", res_text)
                if not match:
                    match = re.search(r"setCookie\(\s*['\"]([^'\"]+)['\"]\s*\)", res_text)

                if match:
                    session_id = match.group(1)
                    self.session.cookies.set("efm_session_id", session_id)

            if session_id:
                self.is_logged_in = True
                return True, f"로그인 성공 (세션 ID: {session_id[:6]}...)"

            if "noauto=1" in res_text or "parent.parent.location" in res_text:
                return False, "로그인 실패: 아이디/비밀번호 불일치 또는 공유기 보안문자(CAPTCHA)가 켜져 있습니다."

            return False, f"로그인 응답을 해석할 수 없습니다: {res_text[:100]}"

        except requests.exceptions.ConnectTimeout:
            return False, f"연결 시간 초과: {self.base_url} 에 연결할 수 없습니다. 공유기 원격접속 포트({self.port}) 설정을 확인하세요."
        except requests.exceptions.ConnectionError:
            return False, f"연결 오류: {self.host}:{self.port} 서버를 찾을 수 없거나 포트가 닫혀 있습니다."
        except Exception as e:
            return False, f"오류 발생: {str(e)}"

    def _fetch_cgi_page(self, path_or_smenu: str, referer: Optional[str] = None) -> str:
        """smenu 이름 또는 상대 URL로 공유기 페이지를 가져옵니다."""
        if path_or_smenu.startswith("http"):
            url = path_or_smenu
        elif "/" in path_or_smenu or "?" in path_or_smenu:
            url = urljoin(f"{self.base_url}/{self.cgi_dir}/", path_or_smenu)
        else:
            url = f"{self.base_url}/{self.cgi_dir}/timepro.cgi?tmenu=iframe&smenu={path_or_smenu}"

        self.session.headers.update({
            "Referer": referer or f"{self.base_url}/{self.cgi_dir}/timepro.cgi?tmenu=main_frame"
        })
        try:
            res = self.session.get(url, timeout=self.timeout)
            if res.status_code == 200 and "login_session.cgi" not in res.text[:300]:
                return res.text
        except Exception:
            pass
        return ""

    def _extract_devices_from_html(self, html: str, source_label: str) -> List[Dict[str, str]]:
        """HTML 테이블(<tr>) 및 JavaScript 데이터에서 (이름, MAC, IP)를 추출합니다."""
        found: List[Dict[str, str]] = []
        if not html:
            return found

        # 1) HTML 테이블 행 파싱
        rows = re.findall(r'<tr[^>]*>(.*?)</tr>', html, re.DOTALL | re.IGNORECASE)
        for row in rows:
            # 헤더/입력폼(MAC 복제 등) 제외
            if "<th" in row.lower():
                continue
            if 'type="text"' in row.lower() or "type=text" in row.lower():
                if "mac" in row.lower() and "checkbox" not in row.lower():
                    continue

            mac_match = MAC_REGEX.search(row)
            if not mac_match:
                continue

            mac = _normalize_mac(mac_match.group(1))
            if not _is_valid_unicast_mac(mac):
                continue

            ip = ""
            for ip_cand in IP_REGEX.findall(row):
                if _is_valid_client_ip(ip_cand):
                    ip = ip_cand
                    break

            cols = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL | re.IGNORECASE)
            clean_cols = [re.sub(r'<.*?>', '', c).replace("&nbsp;", " ").strip() for c in cols]
            name = _pick_device_name(clean_cols, fallback_ip=ip)

            found.append({
                "name": name,
                "mac": mac,
                "ip": ip,
                "source": source_label,
            })

        # 2) JavaScript 인라인 행/배열 파싱 (예: AddRow('192.168.0.2', 'AA:BB:CC:DD:EE:FF', 'MyPC'))
        for line in html.splitlines():
            if "<" in line and ">" in line and "<script" not in line.lower():
                continue
            mac_match = MAC_REGEX.search(line)
            if not mac_match:
                continue
            mac = _normalize_mac(mac_match.group(1))
            if not _is_valid_unicast_mac(mac):
                continue

            ip = ""
            for ip_cand in IP_REGEX.findall(line):
                if _is_valid_client_ip(ip_cand):
                    ip = ip_cand
                    break
            if not ip:
                continue

            str_literals = re.findall(r"['\"]([^'\"]{1,64})['\"]", line)
            name = _pick_device_name(str_literals, fallback_ip=ip)
            found.append({
                "name": name,
                "mac": mac,
                "ip": ip,
                "source": source_label,
            })

        return found

    def get_wol_list(self) -> Tuple[bool, List[Dict[str, str]], str]:
        """공유기에 사전 등록되어 있는 WOL 기기 목록을 가져옵니다."""
        if not self.is_logged_in:
            return False, [], "로그인이 필요합니다."

        try:
            text = self._fetch_cgi_page("expertconfwollist")
            if not text:
                return False, [], "WOL 목록 페이지를 불러오지 못했습니다."

            seen: Set[str] = set()
            unique_devices: List[Dict[str, str]] = []

            rows = re.findall(r'<tr[^>]*>(.*?)</tr>', text, re.DOTALL | re.IGNORECASE)
            for row in rows:
                mac_match = MAC_REGEX.search(row)
                if not mac_match:
                    continue
                mac = _normalize_mac(mac_match.group(1))
                if not _is_valid_unicast_mac(mac) or mac in seen:
                    continue

                cols = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL | re.IGNORECASE)
                clean_cols = [re.sub(r'<.*?>', '', c).replace("&nbsp;", " ").strip() for c in cols]

                # WOL 테이블 구조: [순번, MAC 주소, PC 설명, ...] -> MAC 바로 다음 칸을 PC 설명으로 우선 사용
                name = ""
                for idx, c in enumerate(clean_cols):
                    if MAC_REGEX.search(c):
                        if idx + 1 < len(clean_cols) and clean_cols[idx + 1]:
                            name = clean_cols[idx + 1]
                        break
                if not name:
                    name = _pick_device_name(clean_cols)

                seen.add(mac)
                unique_devices.append({
                    "name": name,
                    "mac": mac,
                    "ip": "",
                    "source": "WOL등록",
                })

            return True, unique_devices, f"WOL 등록 기기 {len(unique_devices)}대 조회"
        except Exception as e:
            return False, [], f"목록 조회 오류: {str(e)}"

    def get_macsearch_devices(self) -> List[Dict[str, str]]:
        """
        ipTIME WOL 페이지 내장 MAC 검색 API(expertconfmacsearch, act=refresh)를 호출해
        공유기가 현재 인식 중인 기기(MAC, IP, PC 이름) 목록을 빠르게 가져옵니다.
        """
        if not self.is_logged_in:
            return []

        url = f"{self.base_url}/{self.cgi_dir}/timepro.cgi"
        self.session.headers.update({
            "Referer": f"{self.base_url}/{self.cgi_dir}/timepro.cgi?tmenu=iframe&smenu=expertconfmacsearch"
        })
        try:
            res = self.session.post(
                url,
                data={
                    "tmenu": "iframe",
                    "smenu": "expertconfmacsearch",
                    "act": "refresh",
                    "inputprefix": "hw",
                },
                timeout=self.timeout,
            )
            if res.status_code != 200 or "login_session.cgi" in res.text[:300]:
                return []
            html = res.text
        except Exception:
            return []

        devices: List[Dict[str, str]] = []
        # 1) SelectMacFromPopup('hw', '74-56-3C-77-BF-22', 'minint-5ap36ic') + 인접 IP(이름) 파싱
        rows = re.findall(r'<tr\b[^>]*>.*?</tr>', html, re.DOTALL | re.IGNORECASE)
        for row in rows:
            m_pop = re.search(
                r"SelectMacFromPopup\(\\?['\"][^'\"]+\\?['\"]\s*,\s*\\?['\"]([0-9A-Fa-f:-]{17})\\?['\"]\s*,\s*\\?['\"]([^'\"]*)\\?['\"]\)",
                row,
            )
            if not m_pop:
                continue
            mac = _normalize_mac(m_pop.group(1))
            if not _is_valid_unicast_mac(mac):
                continue
            pc_name = m_pop.group(2).rstrip("\\").strip()
            ip = ""
            for ip_cand in IP_REGEX.findall(row):
                if _is_valid_client_ip(ip_cand):
                    ip = ip_cand
                    break
            if not pc_name:
                pc_name = f"기기 ({ip})" if ip else "알 수 없는 기기"
            devices.append({
                "name": pc_name,
                "mac": mac,
                "ip": ip,
                "source": "공유기(DHCP/접속)",
            })

        return devices

    def get_router_devices(self) -> Tuple[bool, List[Dict[str, str]], str]:
        """
        공유기의 내장 MAC 검색(expertconfmacsearch), DHCP 할당 현황, 내부 네트워크 설정,
        무선/트래픽 접속 기기 목록을 긁어옵니다.
        """
        if not self.is_logged_in:
            return False, [], "로그인이 필요합니다."

        visited_urls: Set[str] = set()
        merged: Dict[str, Dict[str, str]] = {}

        # 1) ipTIME 공식 WOL 내장 MAC 검색(expertconfmacsearch) 우선 조회
        macsearch_devs = self.get_macsearch_devices()
        if macsearch_devs:
            return True, macsearch_devs, f"공유기 DHCP/접속 목록에서 {len(macsearch_devs)}대 조회"

        candidate_pages = [
            ("netconflansetup", "공유기(DHCP/LAN)"),
            ("netconflan", "공유기(LAN)"),
            ("netconfdhcplist", "공유기(DHCP)"),
            ("dhcplist", "공유기(DHCP)"),
            ("dhcplease", "공유기(DHCP임대)"),
            ("netconflaninfo", "공유기(LAN정보)"),
            ("wirelessconfmacauth", "공유기(무선접속)"),
            ("trafficconfconninfo", "공유기(접속정보)"),
        ]

        # 메뉴 프레임에서 DHCP/LAN/MAC 관련 smenu 추가 탐색
        for menu_frame in ("left_frame", "main_frame"):
            menu_html = self._fetch_cgi_page(f"timepro.cgi?tmenu={menu_frame}")
            if menu_html:
                discovered = re.findall(
                    r"smenu=([a-zA-Z0-9_]*(?:dhcp|lan|lease|mac|conn|client)[a-zA-Z0-9_]*)",
                    menu_html,
                    re.IGNORECASE,
                )
                existing = {p[0].lower() for p in candidate_pages}
                for sm in discovered:
                    if sm.lower() not in existing:
                        existing.add(sm.lower())
                        candidate_pages.append((sm, "공유기(DHCP/접속)"))

        for smenu, label in candidate_pages:
            key = smenu.lower()
            if key in visited_urls:
                continue
            visited_urls.add(key)

            html = self._fetch_cgi_page(smenu)
            if not html:
                continue

            for dev in self._extract_devices_from_html(html, label):
                mac = dev["mac"]
                if mac not in merged:
                    merged[mac] = dev
                else:
                    if not merged[mac].get("ip") and dev.get("ip"):
                        merged[mac]["ip"] = dev["ip"]
                    if merged[mac]["name"].startswith("기기 (") and not dev["name"].startswith("기기 ("):
                        merged[mac]["name"] = dev["name"]

            # 페이지 내 iframe 서브 페이지도 추적
            iframe_srcs = re.findall(r'<iframe[^>]+src=["\']?([^"\'\s>]+)["\']?', html, re.IGNORECASE)
            for src in iframe_srcs:
                if src.lower() in visited_urls:
                    continue
                visited_urls.add(src.lower())
                sub_html = self._fetch_cgi_page(src, referer=f"{self.base_url}/{self.cgi_dir}/timepro.cgi?tmenu=iframe&smenu={smenu}")
                for dev in self._extract_devices_from_html(sub_html, label):
                    mac = dev["mac"]
                    if mac not in merged:
                        merged[mac] = dev
                    else:
                        if not merged[mac].get("ip") and dev.get("ip"):
                            merged[mac]["ip"] = dev["ip"]
                        if merged[mac]["name"].startswith("기기 (") and not dev["name"].startswith("기기 ("):
                            merged[mac]["name"] = dev["name"]

        devices = list(merged.values())
        return True, devices, f"공유기 DHCP/접속 목록에서 {len(devices)}대 조회"

    def get_all_router_devices(self) -> Tuple[bool, List[Dict[str, str]], str]:
        """WOL 등록 기기와 공유기 DHCP/접속 기기 목록을 통합하여 반환합니다."""
        if not self.is_logged_in:
            return False, [], "로그인이 필요합니다."

        ok_wol, wol_devs, wol_msg = self.get_wol_list()
        ok_net, net_devs, net_msg = self.get_router_devices()

        merged: Dict[str, Dict[str, str]] = {}
        for d in wol_devs:
            merged[d["mac"]] = dict(d)

        for d in net_devs:
            mac = d["mac"]
            if mac not in merged:
                merged[mac] = dict(d)
            else:
                if not merged[mac].get("ip") and d.get("ip"):
                    merged[mac]["ip"] = d["ip"]
                if merged[mac]["name"].startswith("기기 (") and not d["name"].startswith("기기 ("):
                    merged[mac]["name"] = d["name"]

        result = list(merged.values())
        return True, result, f"{wol_msg} / {net_msg} (총 {len(result)}대)"

    @staticmethod
    def _parse_input_attrs(tag: str) -> Dict[str, str]:
        """HTML <input> 태그에서 속성(name, type, value)을 추출합니다."""
        attrs: Dict[str, str] = {}
        for m in re.finditer(r'([a-zA-Z0-9_-]+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))', tag):
            key = m.group(1).lower()
            val = m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else m.group(4))
            attrs[key] = val
        return attrs

    def _build_wol_add_payload(self, html: str, clean_mac: str, pc_name: str) -> Optional[Tuple[Dict[str, str], str]]:
        """공유기 WOL 추가 페이지의 <form>을 동적으로 분석해 정확한 POST 페이로드를 생성합니다."""
        forms = re.findall(r'<form[^>]*>.*?</form>', html, re.DOTALL | re.IGNORECASE)
        if not forms:
            forms = [html]

        octets = clean_mac.split(":")
        mac_hyphen = clean_mac.replace(":", "-")

        for form_html in forms:
            inputs = [self._parse_input_attrs(t) for t in re.findall(r'<input\b[^>]*>', form_html, re.IGNORECASE)]
            names = [a.get("name", "") for a in inputs if a.get("name")]
            if not names:
                continue

            # 6칸 분할 MAC 입력 필드(<prefix>1 ~ <prefix>6) 탐색
            name_lower_map = {n.lower(): n for n in names}
            mac_prefix = None
            for n in names:
                m = re.fullmatch(r'([a-zA-Z_]+)1', n)
                if m:
                    prefix = m.group(1)
                    if all(f"{prefix.lower()}{i}" in name_lower_map for i in range(1, 7)):
                        mac_prefix = prefix
                        break

            text_inputs = [
                a.get("name", "")
                for a in inputs
                if a.get("name") and a.get("type", "text").lower() in ("text", "")
            ]

            # MAC 입력창 또는 PC 설명창이 있는 폼만 대상으로 삼음
            has_single_mac = any(k in name_lower_map for k in ("mac", "macaddr", "hwaddr", "wol_mac"))
            if not mac_prefix and not has_single_mac:
                continue

            payload: Dict[str, str] = {}
            for a in inputs:
                iname = a.get("name", "")
                itype = a.get("type", "text").lower()
                if iname and itype == "hidden":
                    payload[iname] = a.get("value", "")

            payload["act"] = "add"

            used_names: Set[str] = set()
            if mac_prefix:
                for idx in range(1, 7):
                    real_name = name_lower_map[f"{mac_prefix.lower()}{idx}"]
                    payload[real_name] = octets[idx - 1]
                    used_names.add(real_name)
            else:
                for cand in ("macaddr", "hwaddr", "wol_mac", "mac"):
                    if cand in name_lower_map:
                        real_name = name_lower_map[cand]
                        payload[real_name] = mac_hyphen
                        used_names.add(real_name)
                        break

            # PC 설명 입력 필드 탐색 (MAC 필드를 제외한 text input)
            desc_candidates = [n for n in text_inputs if n not in used_names]
            desc_field = None
            for n in desc_candidates:
                if re.search(r'(pc|name|desc|host|comment|label)', n, re.IGNORECASE):
                    desc_field = n
                    break
            if not desc_field and desc_candidates:
                desc_field = desc_candidates[0]
            if desc_field:
                payload[desc_field] = pc_name

            # tmenu / smenu 보정
            if "tmenu" not in payload:
                payload["tmenu"] = "expertconf"
            if "smenu" not in payload:
                payload["smenu"] = "remotepc"

            return payload, f"{payload['tmenu']}:{payload['smenu']}"

        return None

    def register_wol(self, mac_address: str, pc_name: str = "MyPC") -> Tuple[bool, str]:
        """
        공유기의 WOL 목록에 기기(MAC + 이름)를 등록합니다(act=add).
        ipTIME의 AddPC() 동작과 동일하게 remotepc 페이지에서 폼 필드명(hw1~hw6, pcname 등)을 확인하고
        expertconfwollist iframe 엔드포인트로 POST 전송합니다.
        """
        if not self.is_logged_in:
            return False, "로그인이 필요합니다."

        clean_mac = _normalize_mac(mac_address)
        if not _is_valid_unicast_mac(clean_mac):
            return False, f"유효하지 않은 MAC 주소입니다: {mac_address}"

        pc_name = (pc_name or "MyPC").strip()[:32]
        octets = clean_mac.split(":")

        # remotepc 폼에서 실제 필드명 감지 (기본값: hw1~hw6, pcname)
        post_data: Dict[str, str] = {
            "tmenu": "iframe",
            "smenu": "expertconfwollist",
            "nomore": "0",
            "act": "add",
        }

        remotepc_html = self._fetch_cgi_page("timepro.cgi?tmenu=expertconf&smenu=remotepc")
        parsed = self._build_wol_add_payload(remotepc_html, clean_mac, pc_name) if remotepc_html else None
        if parsed:
            form_fields, _ = parsed
            for k, v in form_fields.items():
                if k.lower() not in ("tmenu", "smenu", "act", "ocolor"):
                    post_data[k] = v
        else:
            for idx, octet in enumerate(octets, 1):
                post_data[f"hw{idx}"] = octet
            post_data["pcname"] = pc_name

        wol_url = f"{self.base_url}/{self.cgi_dir}/timepro.cgi"
        self.session.headers.update({
            "Referer": f"{self.base_url}/{self.cgi_dir}/timepro.cgi?tmenu=iframe&smenu=expertconfwollist"
        })

        try:
            res = self.session.post(wol_url, data=post_data, timeout=self.timeout)
            if res.status_code != 200:
                return False, f"WOL 등록 실패 (HTTP 상태 코드: {res.status_code})"

            # 실제 등록 반영 여부 검증
            ok_list, current_wol, _ = self.get_wol_list()
            if ok_list and any(d["mac"] == clean_mac for d in current_wol):
                return True, f"공유기 WOL 목록 등록 완료: {pc_name} ({clean_mac})"

            return False, (
                f"등록 요청은 전송되었으나 공유기 WOL 목록에서 '{clean_mac}' 확인에 실패했습니다. "
                "공유기 웹페이지에서 목록을 확인해 주세요."
            )
        except Exception as e:
            return False, f"WOL 등록 오류: {str(e)}"

    def _resolve_wakeup_value(self, clean_mac: str) -> str:
        """공유기 WOL 테이블의 checkbox value 형식(하이픈 vs 콜론)을 맞춥니다."""
        html = self._fetch_cgi_page("expertconfwollist")
        if html:
            target_hex = clean_mac.replace(":", "")
            for val in re.findall(r'name=["\']?wakeupchk["\']?[^>]*value=["\']?([0-9A-Fa-f:-]{17})["\']?', html, re.IGNORECASE):
                if re.sub(r'[^0-9A-Fa-f]', '', val).upper() == target_hex:
                    return val
            for val in re.findall(r'value=["\']?([0-9A-Fa-f:-]{17})["\']?[^>]*name=["\']?wakeupchk', html, re.IGNORECASE):
                if re.sub(r'[^0-9A-Fa-f]', '', val).upper() == target_hex:
                    return val
            # 테이블의 다른 항목이 하이픈을 쓰면 하이픈 형식으로 맞춤
            if re.search(r'[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}', html):
                return clean_mac.replace(":", "-")
        return clean_mac.replace(":", "-")

    def wake(self, mac_address: str, auto_register: bool = False, pc_name: str = "") -> Tuple[bool, str]:
        """
        지정한 MAC 주소의 PC를 켜기 위해 공유기 WOL 명령을 전송합니다.
        auto_register=True일 경우, 공유기 WOL 목록에 없으면 먼저 등록 후 깨웁니다.
        """
        if not self.is_logged_in:
            return False, "로그인이 필요합니다."

        clean_mac = _normalize_mac(mac_address)
        if not _is_valid_unicast_mac(clean_mac):
            return False, f"유효하지 않은 MAC 주소입니다: {mac_address}"

        reg_note = ""
        if auto_register:
            _, current_wol, _ = self.get_wol_list()
            registered_macs = {d["mac"] for d in current_wol}
            if clean_mac not in registered_macs:
                reg_ok, reg_msg = self.register_wol(clean_mac, pc_name or "MyPC")
                if reg_ok:
                    reg_note = " (공유기 WOL 자동 등록 후 송출)"

        wakeup_val = self._resolve_wakeup_value(clean_mac)
        wol_url = f"{self.base_url}/{self.cgi_dir}/timepro.cgi"
        self.session.headers.update({
            "Referer": f"{self.base_url}/{self.cgi_dir}/timepro.cgi?tmenu=iframe&smenu=expertconfwollist"
        })

        post_data = {
            "tmenu": "iframe",
            "smenu": "expertconfwollist",
            "nomore": "0",
            "act": "wake",
            "wakeupchk": wakeup_val
        }

        try:
            res = self.session.post(wol_url, data=post_data, timeout=self.timeout)
            if res.status_code == 200:
                return True, f"WOL 패킷 송출 완료! 대상 MAC: {wakeup_val}{reg_note}"
            else:
                return False, f"WOL 요청 실패 (HTTP 상태 코드: {res.status_code})"
        except Exception as e:
            return False, f"WOL 전송 오류: {str(e)}"


if __name__ == "__main__":
    import sys
    import getpass

    print("=" * 60)
    print("         ipTIME WOL Controller (CLI 모드)         ")
    print("=" * 60)

    host = input("공유기 주소 [기본값: 192.168.0.1]: ").strip() or "192.168.0.1"
    port_input = input("원격 접속 포트 [기본값: 80]: ").strip() or "80"
    port = int(port_input)
    username = input("관리자 아이디 [기본값: admin]: ").strip() or "admin"
    password = getpass.getpass("관리자 비밀번호: ")

    client = IpTimeWOL(host=host, port=port)
    print(f"\n[1] '{host}:{port}' 로그인 시도 중...")
    success, msg = client.login(username, password)
    print(msg)

    if not success:
        sys.exit(1)

    print("\n[2] 공유기 WOL + DHCP/접속 기기 목록 조회 중...")
    ok, devices, list_msg = client.get_all_router_devices()
    print(list_msg)

    target_mac = ""
    if devices:
        print("\n--- 발견된 기기 목록 ---")
        for i, dev in enumerate(devices, 1):
            ip_str = f" | {dev['ip']}" if dev.get("ip") else ""
            print(f"[{i}] {dev['name']} ({dev['mac']}{ip_str}) [{dev['source']}]")
        print("[0] 직접 MAC 주소 입력")

        choice = input("\n깨울 기기 번호 선택 (0 ~ {0}): ".format(len(devices))).strip()
        if choice.isdigit() and 1 <= int(choice) <= len(devices):
            target_mac = devices[int(choice) - 1]["mac"]

    if not target_mac:
        target_mac = input("깨울 PC의 MAC 주소 입력 (예: AA:BB:CC:DD:EE:FF): ").strip()

    if target_mac:
        print(f"\n[3] WOL 신호 전송 중: {target_mac}...")
        wake_ok, wake_msg = client.wake(target_mac, auto_register=True)
        print(wake_msg)
    else:
        print("MAC 주소가 입력되지 않아 취소되었습니다.")
