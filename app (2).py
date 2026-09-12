"""
DDoS Detection & Prevention System - Full Version
-----------------------------------------------------
Features:
- Password protection (pehli baar password set karo, phir har baar login)
- Auto-lock: 30 second koi activity na ho to automatically lock ho jayega
- Faster packet processing (BPF filter se sirf IP packets process hote hain)
- Improved dashboard: graph + top IPs table + protocol breakdown

Run karne ke liye (Admin/sudo permission zaroori hai):
    Windows: python detector_final.py
    Linux/Mac: sudo python3 detector_final.py
"""

import time
import sqlite3
import threading
import hashlib
import os
import math
import socket
import webbrowser
import urllib.request
import json
from datetime import datetime
from collections import deque, Counter

import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from scapy.all import sniff, IP, TCP, UDP, ICMP


# ============================================
# IP INTELLIGENCE (location, ISP, approx distance, approx OS ,which device,VPN\Proxy,Hosting,ASN,etc.)
# ============================================
MY_LOCATION = None   # apni location cache ho jayegi (lat, lon) - ek baar fetch hogi


def get_my_location():
    """Apna (system ka) approximate location fetch karta hai, ek baar cache ho jata hai"""
    global MY_LOCATION
    if MY_LOCATION is not None:
        return MY_LOCATION
    try:
        with urllib.request.urlopen("http://ip-api.com/json/", timeout=4) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                MY_LOCATION = (data.get("lat"), data.get("lon"), data.get("city"), data.get("country"))
    except Exception:
        MY_LOCATION = None
    return MY_LOCATION


def haversine_distance(lat1, lon1, lat2, lon2):
    """Do coordinates ke beech ka distance km me nikalta hai"""
    R = 6371  # Earth radius in km
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def bearing_angle(lat1, lon1, lat2, lon2):
    """Aapki location se target IP ki taraf ka compass angle (degrees) nikalta hai - radar view ke liye"""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dlambda = math.radians(lon2 - lon1)
    x = math.sin(dlambda) * math.cos(phi2)
    y = math.cos(phi1) * math.sin(phi2) - math.sin(phi1) * math.cos(phi2) * math.cos(dlambda)
    bearing = math.degrees(math.atan2(x, y))
    return (bearing + 360) % 360


def get_hostname(ip_address):
    """IP se hostname nikalne ki koshish karta hai (reverse DNS lookup)"""
    try:
        socket.setdefaulttimeout(2)
        host = socket.gethostbyaddr(ip_address)[0]
        return host
    except Exception:
        return "Not available"


def get_ip_details(ip_address):
    """
    Kisi IP ki location, ISP, timezone, hostname, network/ASN, aur
    VPN/Proxy/Hosting/Mobile status nikalta hai.
    Free ip-api.com service use karta hai (private/local IPs ke liye kaam nahi karega).
    """
    result = {
        "country": "Unknown", "city": "Unknown", "region": "Unknown", "isp": "Unknown",
        "distance_km": "N/A", "timezone": "Unknown", "hostname": "Not available",
        "lat": None, "lon": None, "bearing": None,
        "asn_org": "Unknown", "is_vpn_or_proxy": "Unknown",
        "is_hosting": "Unknown", "is_mobile": "Unknown"
    }

    # Private/local IPs (jaise 192.168.x.x, 10.x.x.x) ke liye public location nahi milegi
    if ip_address.startswith(("192.168.", "10.", "127.")) or ip_address.startswith("172."):
        result["country"] = "Local Network"
        result["city"] = "-"
        result["isp"] = "-"
        return result

    result["hostname"] = get_hostname(ip_address)

    try:
        fields = "status,country,regionName,city,isp,timezone,lat,lon,as,org,mobile,proxy,hosting,query"
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip_address}?fields={fields}", timeout=4) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                result["country"] = data.get("country", "Unknown")
                result["city"] = data.get("city", "Unknown")
                result["region"] = data.get("regionName", "Unknown")
                result["isp"] = data.get("isp", "Unknown")
                result["timezone"] = data.get("timezone", "Unknown")
                result["lat"] = data.get("lat")
                result["lon"] = data.get("lon")
                result["asn_org"] = f"{data.get('as', '')} ({data.get('org', 'Unknown')})"
                result["is_vpn_or_proxy"] = "Yes ⚠️" if data.get("proxy") else "No"
                result["is_hosting"] = "Yes (Server/Datacenter)" if data.get("hosting") else "No"
                result["is_mobile"] = "Yes" if data.get("mobile") else "No"

                my_loc = get_my_location()
                if my_loc and data.get("lat") and data.get("lon"):
                    dist = haversine_distance(my_loc[0], my_loc[1], data["lat"], data["lon"])
                    result["distance_km"] = f"{dist:.0f} km"
                    result["bearing"] = bearing_angle(my_loc[0], my_loc[1], data["lat"], data["lon"])
    except Exception:
        pass  # internet na ho ya API fail ho to "Unknown" hi rahega

    return result


def guess_os_from_ttl(ttl):
    """
    TTL value se OS ka rough andaza (100% accurate nahi hai, sirf approximate hint).
    Windows ~128, Linux/Android ~64, macOS/iOS/some routers ~64 ya 255
    """
    if ttl is None:
        return "Unknown"
    if ttl >= 128:
        return "Windows (approx)"
    elif ttl >= 64:
        return "Linux/Android/macOS (approx)"
    elif ttl >= 32:
        return "Older OS (approx)"
    else:
        return "Unknown"


# ============================================
# SETTINGS
# ============================================
TIME_WINDOW = 10
THRESHOLD = 50
DB_NAME = "logs.db"
PASSWORD_FILE = "password.hash"
LOCK_TIMEOUT = 30          # seconds of inactivity before auto-lock


# ============================================
# SHARED DATA
# ============================================
ip_tracker = {}
already_flagged = set()
blocked_ips = set()
protocol_counter = Counter()   # TCP/UDP/ICMP/Other counts

lock = threading.Lock()

total_packets = 0
traffic_history = deque(maxlen=30)
current_second_count = 0


# ============================================
# PASSWORD / AUTHENTICATION HELPERS
# ============================================
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def set_new_password(root):
    """Pehli baar app chalane par password set karwata hai"""
    while True:
        pwd = simpledialog.askstring("Set Password", "ENTER NEW PASSWORD:", show="*", parent=root)
        if pwd is None:
            root.destroy()
            raise SystemExit("Password NOT SET, band kar rahe hain.")
        if len(pwd) < 4:
            messagebox.showwarning("Warning", "Password REQUIRED FOR MINIMUM FOU CHARACTER.")
            continue
        confirm = simpledialog.askstring("Confirm Password", " RE ENTER PASSWORD:", show="*", parent=root)
        if pwd == confirm:
            with open(PASSWORD_FILE, "w") as f:
                f.write(hash_password(pwd))
            messagebox.showinfo("Success", "Password set successfully!")
            return
        else:
            messagebox.showwarning("Warning", "Password match nahi hua, dobara try karo.")


def verify_password(root):
    """Login screen - sahi password na ho to baar baar poochta hai"""
    if not os.path.exists(PASSWORD_FILE):
        set_new_password(root)
        return

    with open(PASSWORD_FILE, "r") as f:
        saved_hash = f.read().strip()

    while True:
        pwd = simpledialog.askstring("Login Required", "Password daalo:", show="*", parent=root)
        if pwd is None:
            root.destroy()
            raise SystemExit("Login cancel ho gaya.")
        if hash_password(pwd) == saved_hash:
            return
        else:
            messagebox.showerror("Error", "Galat password, dobara try karo.")


# ============================================
# DATABASE
# ============================================
def setup_database():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS suspicious_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            request_count INTEGER NOT NULL,
            detected_time TEXT NOT NULL,
            country TEXT,
            city TEXT,
            isp TEXT,
            distance_km TEXT,
            approx_os TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_suspicious_ip(ip_address, request_count, details, approx_os):
    """Database me likhta hai - agar DB busy/locked ho ya koi aur issue ho, crash nahi karega"""
    try:
        conn = sqlite3.connect(DB_NAME, timeout=5)
        cursor = conn.cursor()
        detected_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO suspicious_logs
            (ip_address, request_count, detected_time, country, city, isp, distance_km, approx_os)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip_address, request_count, detected_time,
              details.get("country", "Unknown"), details.get("city", "Unknown"),
              details.get("isp", "Unknown"), details.get("distance_km", "N/A"), approx_os))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Warning] Log save nahi ho payi (ignoring): {e}")


# ============================================
# PACKET PROCESSING (background thread)
# ============================================
def process_packet(packet, app):
    """Har packet process karta hai. Poora function try/except me hai taaki
    kisi ek corrupt/ajeeb packet se poori sniffing thread crash na ho."""
    global total_packets, current_second_count

    try:
        if IP in packet:
            src_ip = packet[IP].src

            # Protocol pehchano (dashboard breakdown ke liye)
            if TCP in packet:
                proto = "TCP"
            elif UDP in packet:
                proto = "UDP"
            elif ICMP in packet:
                proto = "ICMP"
            else:
                proto = "Other"

            with lock:
                protocol_counter[proto] += 1

                if src_ip in blocked_ips:
                    return

                current_time = time.time()
                total_packets += 1
                current_second_count += 1

                if src_ip not in ip_tracker:
                    ip_tracker[src_ip] = {"count": 1, "first_seen": current_time}
                else:
                    time_elapsed = current_time - ip_tracker[src_ip]["first_seen"]
                    if time_elapsed > TIME_WINDOW:
                        ip_tracker[src_ip] = {"count": 1, "first_seen": current_time}
                        already_flagged.discard(src_ip)
                    else:
                        ip_tracker[src_ip]["count"] += 1

                current_count = ip_tracker[src_ip]["count"]
                ttl_value = packet[IP].ttl

                if current_count > THRESHOLD and src_ip not in already_flagged:
                    blocked_ips.add(src_ip)
                    already_flagged.add(src_ip)

            # Lookup (location/ISP) internet call karta hai isliye lock ke BAHAR,
            # taaki dusre packets process hone me atke na
            if current_count > THRESHOLD and src_ip in blocked_ips and src_ip not in getattr(process_packet, "_logged", set()):
                if not hasattr(process_packet, "_logged"):
                    process_packet._logged = set()
                if src_ip not in process_packet._logged:
                    process_packet._logged.add(src_ip)
                    try:
                        approx_os = guess_os_from_ttl(ttl_value)
                        details = get_ip_details(src_ip)
                        log_suspicious_ip(src_ip, current_count, details, approx_os)
                        app.add_alert(src_ip, current_count, details, approx_os)
                    except Exception as e:
                        print(f"[Warning] Alert/lookup me issue (ignoring, sniffing jaari hai): {e}")
    except Exception as e:
        # Koi bhi anjaan error aaye packet processing me, poori thread crash nahi hogi
        print(f"[Warning] Packet process karte waqt error (ignoring): {e}")


def start_sniffing(app):
    """
    Packet capture background thread me chalta hai.
    Agar kisi wajah se sniff() fail/crash ho jaye (jaise adapter disconnect),
    to app crash hone ki bajaye khud ko restart kar leta hai.
    """
    while True:
        try:
            # filter="ip" -> speed improvement: sirf IP packets scapy dega,
            # baaki (ARP, etc.) drop ho jayenge kernel level pe hi
            sniff(prn=lambda pkt: process_packet(pkt, app), store=False, filter="ip")
            break  # agar sniff normally return kare (rare), loop se bahar aa jao
        except PermissionError:
            print("[Error] Admin/root permissions chahiye packet capture ke liye. Sniffing ruk gayi.")
            break
        except Exception as e:
            print(f"[Warning] Sniffing me error, 3 second me dobara try karenge: {e}")
            time.sleep(3)


# ============================================
# GUI APPLICATION
# ============================================
class DDoSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DDoS Detection & Prevention System")
        self.root.geometry("1000x650")

        self.last_activity = time.time()
        self.locked = False

        # ---------- Activity tracking (mouse/keyboard) ----------
        self.root.bind_all("<Motion>", self.reset_activity_timer)
        self.root.bind_all("<Key>", self.reset_activity_timer)
        self.root.bind_all("<Button>", self.reset_activity_timer)

        # ---------- TOP: Stats ----------
        stats_frame = tk.Frame(root, pady=10)
        stats_frame.pack(fill=tk.X)

        self.total_label = tk.Label(stats_frame, text="Total Packets: 0", font=("Arial", 12, "bold"))
        self.total_label.pack(side=tk.LEFT, padx=20)

        self.blocked_label = tk.Label(stats_frame, text="Blocked IPs: 0", font=("Arial", 12, "bold"), fg="red")
        self.blocked_label.pack(side=tk.LEFT, padx=20)

        self.rate_label = tk.Label(stats_frame, text="Rate: 0 pkt/sec", font=("Arial", 12, "bold"), fg="blue")
        self.rate_label.pack(side=tk.LEFT, padx=20)

        self.lock_button = tk.Button(stats_frame, text="🔒 Lock Now", command=self.lock_screen)
        self.lock_button.pack(side=tk.RIGHT, padx=20)

        # ---------- MIDDLE: Graph + Protocol Pie (top row) ----------
        charts_frame = tk.Frame(root)
        charts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Traffic line graph
        graph_frame = tk.Frame(charts_frame)
        graph_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.fig = Figure(figsize=(4.5, 3), dpi=80)
        self.ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Protocol pie chart
        pie_frame = tk.Frame(charts_frame)
        pie_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.fig2 = Figure(figsize=(3.5, 3), dpi=80)
        self.ax2 = self.fig2.add_subplot(111)
        self.canvas2 = FigureCanvasTkAgg(self.fig2, master=pie_frame)
        self.canvas2.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # ---------- BOTTOM: Top IPs table + Alerts list (side by side) ----------
        bottom_frame = tk.Frame(root)
        bottom_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Top talking IPs table
        table_frame = tk.Frame(bottom_frame)
        table_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(table_frame, text="Top Active IPs", font=("Arial", 11, "bold")).pack()

        self.tree = ttk.Treeview(table_frame, columns=("ip", "count"), show="headings", height=10)
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("count", text="Requests (window)")
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Alerts list (Treeview - ek row per alert, click karke details khulengi)
        list_frame = tk.Frame(bottom_frame, width=320)
        list_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(10, 0))

        tk.Label(list_frame, text="Blocked IPs / Alerts  (double-click for details)",
                 font=("Arial", 11, "bold")).pack()

        self.alert_tree = ttk.Treeview(list_frame, columns=("ip", "time"), show="headings", height=12)
        self.alert_tree.heading("ip", text="IP Address")
        self.alert_tree.heading("time", text="Time")
        self.alert_tree.column("ip", width=160)
        self.alert_tree.column("time", width=100)
        self.alert_tree.pack(fill=tk.BOTH, expand=True)
        self.alert_tree.bind("<Double-1>", self.on_alert_double_click)

        # Har alert row ka full data yahan store hoga (row id -> details dict)
        self.alert_data_store = {}

        # ---------- Lock overlay (upar sabke, hidden by default) ----------
        self.lock_overlay = tk.Frame(root, bg="black")

        self.update_gui()
        self.check_idle_timer()

    # -------- Activity / Locking --------
    def reset_activity_timer(self, event=None):
        self.last_activity = time.time()

    def check_idle_timer(self):
        if not self.root.winfo_exists():
            return  # window band ho chuki hai, ab kuch mat karo
        if not self.locked and (time.time() - self.last_activity) > LOCK_TIMEOUT:
            self.lock_screen()
        if self.root.winfo_exists():
            self.root.after(2000, self.check_idle_timer)

    def lock_screen(self):
        if self.locked or not self.root.winfo_exists():
            return
        self.locked = True
        self.lock_overlay.place(x=0, y=0, relwidth=1, relheight=1)
        self.root.update()

        try:
            verify_password(self.root)  # user password daalega yahan
        except SystemExit:
            return  # window band ho gayi login ke dauraan, aage kuch mat karo

        if not self.root.winfo_exists():
            return

        self.lock_overlay.place_forget()
        self.locked = False
        self.reset_activity_timer()

    # -------- Alerts --------
    def add_alert(self, ip, count, details=None, approx_os=None):
        timestamp = datetime.now().strftime("%H:%M:%S")
        full_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        details = details or {}
        approx_os = approx_os or "Unknown"

        def insert_row():
            row_id = self.alert_tree.insert("", 0, values=(ip, timestamp))
            # Is row ki poori detail store kar do, taaki double-click pe nikaal sakein
            self.alert_data_store[row_id] = {
                "ip": ip,
                "count": count,
                "detected_time": full_datetime,
                "country": details.get("country", "Unknown"),
                "city": details.get("city", "Unknown"),
                "region": details.get("region", "Unknown"),
                "isp": details.get("isp", "Unknown"),
                "distance_km": details.get("distance_km", "N/A"),
                "timezone": details.get("timezone", "Unknown"),
                "hostname": details.get("hostname", "Not available"),
                "bearing": details.get("bearing"),
                "lat": details.get("lat"),
                "lon": details.get("lon"),
                "asn_org": details.get("asn_org", "Unknown"),
                "is_vpn_or_proxy": details.get("is_vpn_or_proxy", "Unknown"),
                "is_hosting": details.get("is_hosting", "Unknown"),
                "is_mobile": details.get("is_mobile", "Unknown"),
                "approx_os": approx_os,
            }
            # Naya alert aane par row ko thodi der ke liye highlight/pulse karo (visual feedback)
            self.pulse_row(row_id, 0)

        self.root.after(0, insert_row)

    def pulse_row(self, row_id, step):
        """Naye alert row ko 3 baar red<->normal blink karke dhyan khinchta hai"""
        colors = ["#ffcccc", "white"]
        if step >= 6 or row_id not in self.alert_tree.get_children():
            return
        try:
            self.alert_tree.tag_configure(f"pulse{step % 2}", background=colors[step % 2])
            self.alert_tree.item(row_id, tags=(f"pulse{step % 2}",))
        except tk.TclError:
            return
        self.root.after(200, lambda: self.pulse_row(row_id, step + 1))

    def on_alert_double_click(self, event):
        """Jab kisi alert row pe double-click ho, ek achhi detail window kholta hai"""
        selected = self.alert_tree.selection()
        if not selected:
            return
        row_id = selected[0]
        data = self.alert_data_store.get(row_id)
        if not data:
            return
        self.show_detail_window(data)

    def show_detail_window(self, data):
        """App-jaisi styled detail window - animated radar + poori info dikhati hai"""
        win = tk.Toplevel(self.root)
        win.title(f"Threat Details - {data['ip']}")
        win.geometry("500x960")
        win.configure(bg="#1e1e2f")
        win.resizable(False, False)

        # ---- Fade-in animation (window dheere dheere visible hoti hai) ----
        try:
            win.attributes("-alpha", 0.0)

            def fade(step=0.0):
                if step <= 1.0:
                    win.attributes("-alpha", step)
                    win.after(15, lambda: fade(step + 0.08))
            fade()
        except tk.TclError:
            pass  # kuch systems pe alpha transparency support nahi hoti, tab normal khulega

        # ---- Header (jaise app ka top banner) ----
        header = tk.Frame(win, bg="#e74c3c", height=70)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        tk.Label(header, text="⚠ Threat Detected", bg="#e74c3c", fg="white",
                 font=("Arial", 16, "bold")).pack(pady=(10, 0))
        tk.Label(header, text=data["ip"], bg="#e74c3c", fg="white",
                 font=("Consolas", 13)).pack()

        # ---- Radar/Direction view (LIVE animated) ----
        radar_frame = tk.Frame(win, bg="#1e1e2f")
        radar_frame.pack(pady=(10, 0))

        radar_fig = Figure(figsize=(2.6, 2.6), dpi=80)
        radar_fig.patch.set_facecolor("#1e1e2f")
        radar_ax = radar_fig.add_subplot(111, projection="polar")
        radar_canvas = FigureCanvasTkAgg(radar_fig, master=radar_frame)
        radar_canvas.get_tk_widget().pack()

        bearing = data.get("bearing")
        angle_rad = math.radians(bearing) if bearing is not None else None

        def draw_radar(pulse_radius):
            radar_ax.clear()
            radar_ax.set_facecolor("#1e1e2f")
            radar_ax.set_theta_zero_location("N")
            radar_ax.set_theta_direction(-1)
            radar_ax.set_ylim(0, 1)
            radar_ax.set_yticklabels([])
            radar_ax.set_xticklabels(["N", "", "E", "", "S", "", "W", ""], color="#9a9ab0")
            radar_ax.grid(color="#3a3a55")

            # Center = aap (green dot)
            radar_ax.plot(0, 0, "o", color="#4caf50", markersize=10)

            if angle_rad is not None:
                # Attacker ki direction/distance - pulsing red dot
                radar_ax.plot([angle_rad], [0.75], "o", color="#ff1744", markersize=8 + pulse_radius)
                radar_ax.plot([0, angle_rad], [0, 0.75], color="#ff5252", linewidth=1.5, linestyle="--")
            radar_canvas.draw()

        # Pulsing animation loop - jab tak window khuli hai chalta rahega
        def animate_radar(step=0):
            if not win.winfo_exists():
                return
            pulse = 3 * abs(math.sin(step / 6))
            draw_radar(pulse)
            win.after(150, lambda: animate_radar(step + 1))

        animate_radar()

        # ---- Body (card-style info rows) ----
        body = tk.Frame(win, bg="#1e1e2f", padx=20, pady=10)
        body.pack(fill=tk.BOTH, expand=True)

        def info_row(parent, label, value, value_color="#ffffff"):
            row = tk.Frame(parent, bg="#2a2a3d", pady=7, padx=10)
            row.pack(fill=tk.X, pady=3)
            tk.Label(row, text=label, bg="#2a2a3d", fg="#9a9ab0",
                     font=("Arial", 9, "bold")).pack(anchor="w")
            tk.Label(row, text=value, bg="#2a2a3d", fg=value_color,
                     font=("Arial", 11, "bold")).pack(anchor="w")

        info_row(body, "IP ADDRESS", data["ip"], "#4fc3f7")
        info_row(body, "HOSTNAME", data.get("hostname", "Not available"))
        info_row(body, "REQUEST COUNT (in window)", str(data["count"]), "#ff7043")
        info_row(body, "DETECTED AT", data["detected_time"])
        info_row(body, "LOCATION", f"{data['city']}, {data.get('region', '')}, {data['country']}")
        info_row(body, "TIMEZONE", data.get("timezone", "Unknown"))
        info_row(body, "ISP / NETWORK PROVIDER", data["isp"])
        info_row(body, "NETWORK / ASN (ORGANIZATION)", data.get("asn_org", "Unknown"))
        info_row(body, "APPROX. DISTANCE & DIRECTION",
                 f"{data['distance_km']}" + (f"  (bearing {bearing:.0f}°)" if bearing is not None else ""))
        info_row(body, "DEVICE (APPROX., FROM TTL)", data["approx_os"])

        vpn_color = "#ff5252" if "Yes" in str(data.get("is_vpn_or_proxy", "")) else "#4caf50"
        info_row(body, "VPN / PROXY DETECTED", data.get("is_vpn_or_proxy", "Unknown"), vpn_color)
        info_row(body, "HOSTING / DATACENTER SERVER", data.get("is_hosting", "Unknown"))
        info_row(body, "MOBILE NETWORK", data.get("is_mobile", "Unknown"))

        status_row = tk.Frame(body, bg="#2a2a3d", pady=7, padx=10)
        status_row.pack(fill=tk.X, pady=3)
        tk.Label(status_row, text="STATUS", bg="#2a2a3d", fg="#9a9ab0",
                 font=("Arial", 9, "bold")).pack(anchor="w")
        tk.Label(status_row, text="🔒 BLOCKED", bg="#2a2a3d", fg="#4caf50",
                 font=("Arial", 12, "bold")).pack(anchor="w")

        # ---- Map + Refresh + Close buttons ----
        btn_row = tk.Frame(win, bg="#1e1e2f")
        btn_row.pack(pady=10)

        lat, lon = data.get("lat"), data.get("lon")

        def open_map():
            if lat and lon:
                webbrowser.open(f"https://www.google.com/maps?q={lat},{lon}")
            else:
                messagebox.showinfo("Map Not Available",
                                     "Is IP (local network ya lookup fail) ki exact coordinates nahi mili.")

        def refresh_location():
            """Dobara IP lookup karke updated location laata hai (background thread me)"""
            def worker():
                new_details = get_ip_details(data["ip"])
                data.update({
                    "country": new_details.get("country", data["country"]),
                    "city": new_details.get("city", data["city"]),
                    "isp": new_details.get("isp", data["isp"]),
                    "distance_km": new_details.get("distance_km", data["distance_km"]),
                    "lat": new_details.get("lat"),
                    "lon": new_details.get("lon"),
                    "is_vpn_or_proxy": new_details.get("is_vpn_or_proxy", data.get("is_vpn_or_proxy")),
                })
                if win.winfo_exists():
                    win.after(0, lambda: messagebox.showinfo("Refreshed", "Location dobara check ho gayi. Window band karke dobara kholo updated info dekhne ke liye."))
            threading.Thread(target=worker, daemon=True).start()

        tk.Button(btn_row, text="🗺 View on Map", command=open_map, bg="#2196F3", fg="white",
                  font=("Arial", 10, "bold"), relief=tk.FLAT, padx=15, pady=6).pack(side=tk.LEFT, padx=5)

        tk.Button(btn_row, text="🔄 Refresh Location", command=refresh_location, bg="#607d8b", fg="white",
                  font=("Arial", 10, "bold"), relief=tk.FLAT, padx=15, pady=6).pack(side=tk.LEFT, padx=5)

        tk.Button(btn_row, text="Close", command=win.destroy, bg="#e74c3c", fg="white",
                  font=("Arial", 10, "bold"), relief=tk.FLAT, padx=15, pady=6).pack(side=tk.LEFT, padx=5)

    # -------- Periodic GUI update --------
    def update_gui(self):
        global current_second_count

        if not self.root.winfo_exists():
            return  # window band ho chuki hai

        with lock:
            packets_this_second = current_second_count
            current_second_count = 0
            total = total_packets
            blocked_count = len(blocked_ips)
            top_ips = sorted(ip_tracker.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
            proto_snapshot = dict(protocol_counter)

        traffic_history.append(packets_this_second)

        self.total_label.config(text=f"Total Packets: {total}")
        self.blocked_label.config(text=f"Blocked IPs: {blocked_count}")
        self.rate_label.config(text=f"Rate: {packets_this_second} pkt/sec")

        # Line graph
        self.ax.clear()
        self.ax.plot(list(traffic_history), color="#2196F3")
        self.ax.set_title("Live Traffic (pkt/sec)")
        self.canvas.draw()

        # Pie chart
        self.ax2.clear()
        if proto_snapshot:
            self.ax2.pie(proto_snapshot.values(), labels=proto_snapshot.keys(), autopct="%1.0f%%")
        self.ax2.set_title("Protocol Breakdown")
        self.canvas2.draw()

        # Top IPs table
        self.tree.delete(*self.tree.get_children())
        for ip_addr, data in top_ips:
            self.tree.insert("", tk.END, values=(ip_addr, data["count"]))

        if self.root.winfo_exists():
            self.root.after(1000, self.update_gui)


# ============================================
# MAIN
# ============================================
def handle_gui_exception(exc, val, tb):
    """
    Tkinter me kisi bhi button click/timer callback ke andar agar
    anjaan error aaye, to poori app crash hone ki bajaye sirf
    terminal me warning print hogi aur app chalti rahegi.
    """
    import traceback
    print("[Warning] Ek GUI error aayi, ignore karke aage badh rahe hain:")
    traceback.print_exception(exc, val, tb)


if __name__ == "__main__":
    setup_database()

    root = tk.Tk()
    root.report_callback_exception = handle_gui_exception  # crash-proofing
    root.withdraw()  # login/setup poora hone tak main window chhupao

    try:
        verify_password(root)  # pehli baar password set karwayega, warna login lega
    except SystemExit:
        raise  # user ne khud cancel kiya, ye normal exit hai

    root.deiconify()  # ab main window dikhao
    app = DDoSApp(root)

    sniff_thread = threading.Thread(target=start_sniffing, args=(app,), daemon=True)
    sniff_thread.start()

    root.mainloop()
