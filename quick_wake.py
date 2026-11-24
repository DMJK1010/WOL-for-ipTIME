"""
ipTIME WOL 즉시 실행기 (원클릭 백그라운드용)
config.json에 저장된 설정값으로 바로 공유기에 접속하여 대상 PC를 켭니다.
윈도우 시작프로그램, 바로가기 키(단축키), 작업 스케줄러 등록용으로 유용합니다.
"""

import sys
import os
import json
from iptime_wol import IpTimeWOL

def main():
    app_dir = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(app_dir, "config.json")
    if not os.path.exists(config_path):
        print(f"[오류] {config_path} 파일이 없습니다. 먼저 gui.py 또는 iptime_wol.py를 실행하여 설정을 저장하세요.")
        sys.exit(1)

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:
        print(f"[오류] 설정 파일 읽기 실패: {e}")
        sys.exit(1)

    host = cfg.get("host", "your-ddns.iptime.org")
    port = int(cfg.get("port", 8080))
    user = cfg.get("username", "admin")
    pw = cfg.get("password", "")
    target_mac = cfg.get("target_mac", "")

    if not pw:
        print("[오류] config.json 에 비밀번호가 비어있습니다. gui.py에서 입력 후 저장해주세요.")
        sys.exit(1)

    if not target_mac:
        print("[오류] config.json 에 대상 PC MAC 주소가 비어있습니다.")
        sys.exit(1)

    print(f"[*] ipTIME({host}:{port}) 접속 중...")
    client = IpTimeWOL(host=host, port=port)
    ok, msg = client.login(user, pw)
    print(f"[*] {msg}")

    if not ok:
        sys.exit(1)

    print(f"[*] MAC({target_mac}) PC 켜기 명령 전송 중...")
    wake_ok, wake_msg = client.wake(target_mac)
    print(f"[결과] {wake_msg}")

    if not wake_ok:
        sys.exit(1)

if __name__ == "__main__":
    main()
