"""
ipTIME WOL GUI Controller
기능:
1. 공유기 원격 접속 후 WOL 등록 목록 + DHCP 할당 현황 / 접속 기기 목록 일괄 조회
2. 내부망(LAN) ARP 스캔으로 켜져 있는 기기 MAC/IP/호스트명 자동 탐색
3. MAC 주소별 사용자 지정 이름(별칭) 저장 및 관리 (config.json)
4. 미등록 기기 자동 WOL 등록 및 원클릭 원격 부팅
"""

import os
import json
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from typing import Dict

from iptime_wol import IpTimeWOL, _normalize_mac, _is_valid_unicast_mac
from lan_scanner import scan_lan_arp

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")


class WolGuiApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("ipTIME WOL Controller")
        self.root.geometry("680x760")
        self.root.minsize(600, 660)

        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.bg_color = "#f8f9fa"
        self.root.configure(bg=self.bg_color)

        self.client = None
        # mac -> {"name": str, "mac": str, "ip": str, "source": str}
        self.discovered_devices: Dict[str, Dict[str, str]] = {}
        # mac -> {"name": str, "ip": str}
        self.aliases: Dict[str, Dict[str, str]] = {}

        self._create_widgets()
        self.load_config()

    def _create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="14 14 14 14")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 타이틀
        title_label = tk.Label(
            main_frame,
            text="⚡ ipTIME WOL PC 원격 부팅",
            font=("Malgun Gothic", 15, "bold"),
            bg=self.bg_color,
            fg="#1f2937"
        )
        title_label.pack(anchor="w", pady=(0, 10))

        # 1. 공유기 접속 설정 그룹
        router_group = ttk.LabelFrame(main_frame, text=" 1. 공유기 접속 정보 ", padding="10 8")
        router_group.pack(fill=tk.X, pady=(0, 8))

        host_frame = ttk.Frame(router_group)
        host_frame.pack(fill=tk.X, pady=3)
        ttk.Label(host_frame, text="공유기 주소 (DDNS):", width=18).pack(side=tk.LEFT)
        self.host_var = tk.StringVar(value="your-ddns.iptime.org")
        ttk.Entry(host_frame, textvariable=self.host_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        ttk.Label(host_frame, text="원격 포트:").pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value="8080")
        ttk.Entry(host_frame, textvariable=self.port_var, width=7).pack(side=tk.LEFT)

        auth_frame = ttk.Frame(router_group)
        auth_frame.pack(fill=tk.X, pady=3)
        ttk.Label(auth_frame, text="관리자 아이디:", width=18).pack(side=tk.LEFT)
        self.user_var = tk.StringVar(value="admin")
        ttk.Entry(auth_frame, textvariable=self.user_var, width=15).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(auth_frame, text="비밀번호:").pack(side=tk.LEFT)
        self.pw_var = tk.StringVar(value="")
        self.pw_entry = ttk.Entry(auth_frame, textvariable=self.pw_var, show="*")
        self.pw_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        self.show_pw_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            auth_frame,
            text="표시",
            variable=self.show_pw_var,
            command=self.toggle_show_pw
        ).pack(side=tk.LEFT)

        btn_box = ttk.Frame(router_group)
        btn_box.pack(fill=tk.X, pady=(4, 0))
        self.save_btn = ttk.Button(btn_box, text="접속 설정 저장", command=lambda: self.save_config(show_popup=True))
        self.save_btn.pack(side=tk.LEFT)

        # 2. 기기 탐색 및 목록 테이블
        scan_group = ttk.LabelFrame(main_frame, text=" 2. 기기 찾기 (공유기 DHCP/접속 + 내부망 ARP 스캔) ", padding="10 8")
        scan_group.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        scan_btn_frame = ttk.Frame(scan_group)
        scan_btn_frame.pack(fill=tk.X, pady=(0, 6))

        self.fetch_btn = ttk.Button(
            scan_btn_frame,
            text="🌐 공유기 조회 (WOL + DHCP/접속기기)",
            command=self.start_fetch_devices
        )
        self.fetch_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.arp_btn = ttk.Button(
            scan_btn_frame,
            text="🔍 내부망 ARP 스캔",
            command=self.start_arp_scan
        )
        self.arp_btn.pack(side=tk.LEFT)

        # 기기 목록 Treeview
        tree_frame = ttk.Frame(scan_group)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("name", "mac", "ip", "source")
        self.device_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=7, selectmode="browse")
        self.device_tree.heading("name", text="이름 (별칭)")
        self.device_tree.heading("mac", text="MAC 주소")
        self.device_tree.heading("ip", text="IP 주소")
        self.device_tree.heading("source", text="출처")

        self.device_tree.column("name", width=180, anchor="w")
        self.device_tree.column("mac", width=140, anchor="center")
        self.device_tree.column("ip", width=115, anchor="center")
        self.device_tree.column("source", width=130, anchor="center")

        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.device_tree.yview)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.device_tree.configure(yscrollcommand=tree_scroll.set)
        self.device_tree.bind("<<TreeviewSelect>>", self.on_tree_selected)

        # 3. 대상 PC 선택 및 이름(별칭) 지정
        pc_group = ttk.LabelFrame(main_frame, text=" 3. 대상 PC 및 이름(별칭) 설정 ", padding="10 8")
        pc_group.pack(fill=tk.X, pady=(0, 10))

        mac_frame = ttk.Frame(pc_group)
        mac_frame.pack(fill=tk.X, pady=3)
        ttk.Label(mac_frame, text="대상 MAC 주소:", width=16).pack(side=tk.LEFT)
        self.mac_var = tk.StringVar(value="")
        ttk.Entry(mac_frame, textvariable=self.mac_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        self.reg_btn = ttk.Button(mac_frame, text="공유기 WOL에 등록", command=self.start_register_wol)
        self.reg_btn.pack(side=tk.LEFT)

        name_frame = ttk.Frame(pc_group)
        name_frame.pack(fill=tk.X, pady=3)
        ttk.Label(name_frame, text="기기 이름 (별칭):", width=16).pack(side=tk.LEFT)
        self.alias_var = tk.StringVar(value="")
        ttk.Entry(name_frame, textvariable=self.alias_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        self.save_alias_btn = ttk.Button(name_frame, text="이름 저장", command=self.save_alias)
        self.save_alias_btn.pack(side=tk.LEFT, padx=(0, 4))

        self.del_alias_btn = ttk.Button(name_frame, text="삭제", width=6, command=self.delete_alias)
        self.del_alias_btn.pack(side=tk.LEFT)

        opt_frame = ttk.Frame(pc_group)
        opt_frame.pack(fill=tk.X, pady=(4, 0))
        self.auto_reg_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            opt_frame,
            text="미등록 기기일 경우 공유기에 자동 등록(act=add) 후 부팅 신호 전송",
            variable=self.auto_reg_var
        ).pack(side=tk.LEFT)

        # 4. 메인 실행 버튼 (WOL)
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=(0, 10))

        self.wake_btn = tk.Button(
            action_frame,
            text="⚡ 지금 PC 켜기 (WOL 실행)",
            font=("Malgun Gothic", 12, "bold"),
            bg="#2563eb",
            fg="white",
            activebackground="#1d4ed8",
            activeforeground="white",
            relief=tk.RAISED,
            cursor="hand2",
            height=2,
            command=self.start_wake_pc
        )
        self.wake_btn.pack(fill=tk.X)

        # 5. 상태 및 로그 출력창
        log_group = ttk.LabelFrame(main_frame, text=" 진행 상황 및 로그 ", padding="6 6")
        log_group.pack(fill=tk.BOTH, expand=False)

        self.log_text = tk.Text(log_group, wrap=tk.WORD, font=("Consolas", 9), height=7, bg="#ffffff", fg="#333333")
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(log_group, command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar.set)

    def log(self, message: str):
        now = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{now}] {message}\n")
        self.log_text.see(tk.END)

    def log_async(self, message: str):
        self.root.after(0, lambda m=message: self.log(m))

    def toggle_show_pw(self):
        self.pw_entry.config(show="" if self.show_pw_var.get() else "*")

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    self.host_var.set(cfg.get("host", "your-ddns.iptime.org"))
                    self.port_var.set(str(cfg.get("port", 8080)))
                    self.user_var.set(cfg.get("username", "admin"))
                    self.pw_var.set(cfg.get("password", ""))
                    saved_mac = cfg.get("target_mac", "")
                    self.mac_var.set(saved_mac)

                    raw_aliases = cfg.get("aliases", {})
                    if isinstance(raw_aliases, dict):
                        for mac_k, val in raw_aliases.items():
                            norm = _normalize_mac(mac_k)
                            if isinstance(val, dict):
                                self.aliases[norm] = {
                                    "name": val.get("name", norm),
                                    "ip": val.get("ip", "")
                                }
                            elif isinstance(val, str):
                                self.aliases[norm] = {"name": val, "ip": ""}

                    for mac, info in self.aliases.items():
                        self.discovered_devices[mac] = {
                            "name": info["name"],
                            "mac": mac,
                            "ip": info.get("ip", ""),
                            "source": "저장된 기기"
                        }
                    self.refresh_device_table()

                    if saved_mac and _normalize_mac(saved_mac) in self.aliases:
                        self.alias_var.set(self.aliases[_normalize_mac(saved_mac)]["name"])

                    self.log("기존 설정 및 저장된 기기 별칭을 불러왔습니다.")
            except Exception as e:
                self.log(f"설정 불러오기 실패: {e}")
        else:
            self.log("준비 완료. '공유기 조회' 또는 '내부망 ARP 스캔'으로 기기를 찾아보세요.")

    def save_config(self, show_popup: bool = False):
        try:
            port = int(self.port_var.get().strip() or "8080")
        except ValueError:
            messagebox.showerror("오류", "포트 번호는 숫자여야 합니다.")
            return

        cfg = {
            "host": self.host_var.get().strip(),
            "port": port,
            "username": self.user_var.get().strip(),
            "password": self.pw_var.get(),
            "target_mac": self.mac_var.get().strip(),
            "aliases": self.aliases
        }

        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=4, ensure_ascii=False)
            self.log("설정이 config.json 에 저장되었습니다.")
            if show_popup:
                messagebox.showinfo("저장 완료", "설정이 성공적으로 저장되었습니다.")
        except Exception as e:
            if show_popup:
                messagebox.showerror("저장 오류", f"설정 저장 실패: {e}")
            else:
                self.log(f"설정 저장 오류: {e}")

    def merge_devices(self, new_devices):
        """새로 탐색한 기기 목록을 기존 목록과 병합하고 별칭을 우선 적용합니다."""
        for d in new_devices:
            mac = _normalize_mac(d.get("mac", ""))
            if not _is_valid_unicast_mac(mac):
                continue

            ip = d.get("ip", "")
            src = d.get("source", "")
            raw_name = d.get("name", "")

            if mac not in self.discovered_devices:
                self.discovered_devices[mac] = {
                    "name": raw_name,
                    "mac": mac,
                    "ip": ip,
                    "source": src,
                }
            else:
                existing = self.discovered_devices[mac]
                if ip:
                    existing["ip"] = ip
                if src and src not in existing["source"]:
                    if existing["source"] == "저장된 기기":
                        existing["source"] = src
                    else:
                        existing["source"] = f"{existing['source']}, {src}"
                if existing["name"].startswith("기기 (") and raw_name and not raw_name.startswith("기기 ("):
                    existing["name"] = raw_name

        # 별칭(사용자 지정 이름)이 있으면 최우선 반영
        for mac, info in self.aliases.items():
            if mac in self.discovered_devices:
                self.discovered_devices[mac]["name"] = info["name"]
                if not self.discovered_devices[mac].get("ip") and info.get("ip"):
                    self.discovered_devices[mac]["ip"] = info["ip"]

        self.refresh_device_table()

    def refresh_device_table(self):
        selected_mac = _normalize_mac(self.mac_var.get()) if self.mac_var.get().strip() else ""
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)

        # 정렬: 별칭 저장 기기 / WOL등록 우선, 그 외 이름순
        def _sort_key(item_dict):
            src = item_dict.get("source", "")
            is_named = item_dict["mac"] in self.aliases
            is_wol = "WOL등록" in src
            return (0 if is_named else 1, 0 if is_wol else 1, item_dict.get("ip", ""), item_dict.get("name", ""))

        sorted_devs = sorted(self.discovered_devices.values(), key=_sort_key)
        for d in sorted_devs:
            display_name = self.aliases[d["mac"]]["name"] if d["mac"] in self.aliases else d["name"]
            iid = self.device_tree.insert(
                "",
                tk.END,
                values=(display_name, d["mac"], d.get("ip", ""), d.get("source", ""))
            )
            if d["mac"] == selected_mac:
                self.device_tree.selection_set(iid)
                self.device_tree.see(iid)

    def on_tree_selected(self, event):
        sel = self.device_tree.selection()
        if not sel:
            return
        values = self.device_tree.item(sel[0], "values")
        if len(values) >= 2:
            name, mac = values[0], values[1]
            self.mac_var.set(mac)
            self.alias_var.set(name)

    def save_alias(self):
        raw_mac = self.mac_var.get().strip()
        if not raw_mac or not _is_valid_unicast_mac(raw_mac):
            messagebox.showwarning("MAC 확인", "유효한 MAC 주소를 먼저 입력하거나 목록에서 선택하세요.")
            return

        mac = _normalize_mac(raw_mac)
        name = self.alias_var.get().strip()
        if not name:
            messagebox.showwarning("이름 확인", "저장할 기기 이름(별칭)을 입력하세요.")
            return

        ip = self.discovered_devices.get(mac, {}).get("ip", "") or self.aliases.get(mac, {}).get("ip", "")
        self.aliases[mac] = {"name": name, "ip": ip}
        if mac not in self.discovered_devices:
            self.discovered_devices[mac] = {
                "name": name,
                "mac": mac,
                "ip": ip,
                "source": "저장된 기기"
            }
        else:
            self.discovered_devices[mac]["name"] = name

        self.mac_var.set(mac)
        self.refresh_device_table()
        self.save_config(show_popup=False)
        self.log(f"이름 저장 완료: '{name}' ({mac})")

    def delete_alias(self):
        raw_mac = self.mac_var.get().strip()
        if not raw_mac:
            return
        mac = _normalize_mac(raw_mac)
        if mac in self.aliases:
            removed = self.aliases.pop(mac)
            if self.discovered_devices.get(mac, {}).get("source") == "저장된 기기":
                self.discovered_devices.pop(mac, None)
            self.refresh_device_table()
            self.save_config(show_popup=False)
            self.log(f"저장된 이름 삭제됨: '{removed['name']}' ({mac})")
        else:
            self.log("목록에 저장된 별칭이 없습니다.")

    def _get_or_login_client(self) -> IpTimeWOL:
        host = self.host_var.get().strip()
        port = int(self.port_var.get().strip())
        user = self.user_var.get().strip()
        pw = self.pw_var.get()

        if self.client and self.client.is_logged_in and self.client.host == host and self.client.port == port:
            return self.client

        self.log_async(f"공유기 ({host}:{port}) 로그인 시도 중...")
        client = IpTimeWOL(host=host, port=port)
        ok, msg = client.login(user, pw)
        self.log_async(msg)
        if not ok:
            return None
        self.client = client
        return client

    def start_fetch_devices(self):
        self.fetch_btn.config(state=tk.DISABLED)
        threading.Thread(target=self._fetch_devices_worker, daemon=True).start()

    def _fetch_devices_worker(self):
        try:
            try:
                int(self.port_var.get().strip())
            except ValueError:
                self.log_async("포트 번호 오류: 유효한 숫자를 입력하세요.")
                return

            client = self._get_or_login_client()
            if not client:
                return

            self.log_async("공유기 WOL 목록 및 DHCP/접속 기기 목록 긁어오는 중...")
            ok, devices, list_msg = client.get_all_router_devices()
            self.log_async(list_msg)

            if ok:
                self.root.after(0, lambda d=devices: self.merge_devices(d))
                if not devices:
                    self.log_async("안내: 공유기에서 조회된 기기가 없습니다. 집 안이라면 '내부망 ARP 스캔'을 눌러보세요.")
        finally:
            self.root.after(0, lambda: self.fetch_btn.config(state=tk.NORMAL))

    def start_arp_scan(self):
        self.arp_btn.config(state=tk.DISABLED)
        self.log("내부망(LAN) ARP 스캔 시작 중... (약 3~5초 소요)")
        threading.Thread(target=self._arp_scan_worker, daemon=True).start()

    def _arp_scan_worker(self):
        try:
            ok, devices, msg = scan_lan_arp()
            self.log_async(msg)
            if ok and devices:
                self.root.after(0, lambda d=devices: self.merge_devices(d))
        except Exception as e:
            self.log_async(f"ARP 스캔 오류: {e}")
        finally:
            self.root.after(0, lambda: self.arp_btn.config(state=tk.NORMAL))

    def start_register_wol(self):
        raw_mac = self.mac_var.get().strip()
        if not raw_mac or not _is_valid_unicast_mac(raw_mac):
            messagebox.showwarning("MAC 확인", "공유기에 등록할 유효한 MAC 주소를 입력하세요.")
            return
        self.reg_btn.config(state=tk.DISABLED)
        threading.Thread(target=self._register_wol_worker, daemon=True).start()

    def _register_wol_worker(self):
        try:
            mac = _normalize_mac(self.mac_var.get().strip())
            pc_name = self.alias_var.get().strip() or self.discovered_devices.get(mac, {}).get("name", "MyPC")
            client = self._get_or_login_client()
            if not client:
                return

            ok, msg = client.register_wol(mac, pc_name)
            self.log_async(msg)
            if ok:
                self.root.after(0, lambda: self.merge_devices([{"name": pc_name, "mac": mac, "ip": "", "source": "WOL등록"}]))
                self.root.after(0, lambda: messagebox.showinfo("등록 완료", msg))
            else:
                self.root.after(0, lambda: messagebox.showerror("등록 실패", msg))
        finally:
            self.root.after(0, lambda: self.reg_btn.config(state=tk.NORMAL))

    def start_wake_pc(self):
        target_mac = self.mac_var.get().strip()
        if not target_mac or not _is_valid_unicast_mac(target_mac):
            self.log("오류: 깨울 대상 PC의 유효한 MAC 주소를 입력하거나 목록에서 선택하세요.")
            messagebox.showwarning("입력 필요", "깨울 PC의 유효한 MAC 주소를 입력하세요.")
            return

        self.wake_btn.config(state=tk.DISABLED)
        threading.Thread(target=self._wake_pc_worker, daemon=True).start()

    def _wake_pc_worker(self):
        try:
            try:
                int(self.port_var.get().strip())
            except ValueError:
                self.log_async("포트 번호 오류")
                return

            target_mac = _normalize_mac(self.mac_var.get().strip())
            pc_name = self.alias_var.get().strip() or self.discovered_devices.get(target_mac, {}).get("name", "MyPC")
            auto_reg = self.auto_reg_var.get()

            client = self._get_or_login_client()
            if not client:
                return

            self.log_async(f"MAC: {target_mac} ({pc_name}) 에 WOL 신호 전송 요청 중...")
            wake_ok, wake_msg = client.wake(target_mac, auto_register=auto_reg, pc_name=pc_name)
            self.log_async(wake_msg)

            if wake_ok:
                if self.alias_var.get().strip():
                    self.aliases[target_mac] = {
                        "name": self.alias_var.get().strip(),
                        "ip": self.discovered_devices.get(target_mac, {}).get("ip", "")
                    }
                self.root.after(0, lambda: self.save_config(show_popup=False))
                self.root.after(0, lambda m=wake_msg: messagebox.showinfo("성공", m))
            else:
                self.root.after(0, lambda m=wake_msg: messagebox.showerror("전송 실패", m))
        finally:
            self.root.after(0, lambda: self.wake_btn.config(state=tk.NORMAL))


def main():
    root = tk.Tk()
    app = WolGuiApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
