# HƯỚNG DẪN TRIỂN KHAI ANTI-DDOS TCP FIREWALL v3.5
*(Chạy đa nền tảng: Linux VPS & Windows)*

Dự án này là hệ thống **Firewall kiêm TCP Reverse Proxy trung gian** chuyên dụng để đặt trên VPS chặn trước Server Game gốc, có khả năng gánh tải, phát hiện và phân tán các đợt tấn công DDoS TCP Flood với **8 lớp bảo vệ chuyên sâu**.

---

## 1. Cấu Trúc Thư Mục Build Sẵn Trong `bin/`

Trong thư mục `D:\MOD BUILD\FW\bin\`:
* `firewall.exe`: File chạy trực tiếp trên **Windows** (x86_64).
* `firewall-linux-amd64`: File chạy trực tiếp trên **Linux VPS** (Ubuntu, Debian, CentOS, Rocky Linux).
* `config.txt`: File cấu hình toàn bộ thông số port, IP và thuật toán.
* `whitelist.txt`: Danh sách IP tin cậy (Admin, máy chủ thanh toán, IP nội bộ).
* `blacklist.txt`: Danh sách IP bị cấm vĩnh viễn (tự động cập nhật khi phát hiện botnet).

---

## 2. Cách Cấu Hình Để Cắm Vào VPS Trung Gian Nối Ra Server Game Gốc

Mở file `config.txt`:
```ini
# Port firewall lắng nghe trên VPS trung gian để Client Game kết nối vào
firewall_host=0.0.0.0
firewall_port=9999

# IP & Port của Server Game Gốc cần bảo vệ (nơi chạy logic game thực sự)
backend_host=103.xxx.xxx.xxx
backend_port=14445
```

> **Nguyên lý hoạt động:**
> - Toàn bộ người chơi sẽ kết nối vào IP VPS Trung Gian (`firewall_host:9999`).
> - Firewall sẽ lọc sạch các kết nối botnet, SYN flood, socket ngoại (SOCKS/HTTP proxy).
> - Chỉ những kết nối hợp lệ mới được chuyển tiếp (forward) về Server Game gốc (`backend_host:14445`).
> - IP thật của Server Game gốc hoàn toàn được giấu kín sau VPS trung gian.

---

## 3. Hướng Dẫn Chạy Trên Windows

1. Mở Command Prompt (`cmd`) hoặc PowerShell với quyền **Run as Administrator** (để firewall có quyền gọi Kernel-level drop bằng Windows Firewall `netsh`).
2. Di chuyển vào thư mục:
   ```cmd
   cd /d "D:\MOD BUILD\FW\bin"
   ```
3. Khởi động Firewall:
   ```cmd
   firewall.exe
   ```
   Hoặc ghi đè trực tiếp tham số qua dòng lệnh:
   ```cmd
   firewall.exe -listen 0.0.0.0:9999 -backend 103.xxx.xxx.xxx:14445
   ```

---

## 4. Hướng Dẫn Chạy Trên Linux VPS (Ubuntu / Debian / CentOS)

### Bước 1: Copy file lên VPS
Dùng WinSCP / FileZilla / SCP để đẩy 3 file lên thư mục `/opt/firewall`:
- `firewall-linux-amd64`
- `config.txt`
- `whitelist.txt`

### Bước 2: Cấp quyền thực thi và chạy thử
```bash
cd /opt/firewall
chmod +x firewall-linux-amd64

# Chạy với quyền root (để kích hoạt iptables kernel blocking):
sudo ./firewall-linux-amd64
```

### Bước 3: Cài đặt làm Service tự khởi động (Systemd Service)
Tạo file service:
```bash
sudo nano /etc/systemd/system/game-firewall.service
```
Dán nội dung sau:
```ini
[Unit]
Description=Anti-DDoS TCP Proxy Firewall for Game Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/firewall
ExecStart=/opt/firewall/firewall-linux-amd64 -config /opt/firewall/config.txt
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Kích hoạt và chạy service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable game-firewall
sudo systemctl start game-firewall

# Xem log hoạt động thời gian thực:
sudo journalctl -u game-firewall -f
```

---

## 5. Tóm Tắt 8 Lớp Bảo Vệ & Tính Năng Chống DDoS

1. **Layer 1 (Access Control):** Whitelist/Blacklist hỗ trợ cả IP đơn và dải CIDR (`10.0.0.0/8`, `/24`), tự động hot-reload mỗi 60s không làm gián đoạn game.
2. **Layer 2 (Rate Limiting):** Phân chia quota kết nối giữa IP Whitelist (200 conns) và IP ngoài (5 conns, 3 conn/s, 50 gói/s).
3. **Layer 3 (Half-Open SYN Defense):** Đặt deadline 3 giây cho kết nối gửi gói tin đầu tiên; nếu chỉ mở TCP 3-way handshake rồi treo socket để làm nghẽn server (SYN Flood) $\rightarrow$ Đóng ngay lập tức và phạt điểm.
4. **Layer 4 (Attack Signature Engine):** 29 chữ ký tấn công chuyên sâu:
   - Chặn **Socket Ngoại** (SOCKS4, SOCKS4a, SOCKS5, HTTP CONNECT proxy, Shadowsocks).
   - Chặn tool flood (LOIC, HOIC, Slowloris, RUDY, MHDDoS, Hammer Head, Xerxes, Tor's Hammer).
   - Quét Entropy (chặn các luồng byte ngẫu nhiên rác hoặc uniform byte `0x00`, `0xFF`, `0x41`...).
5. **Layer 5 (Behavioral Analysis):** Cơ chế tích lũy điểm phạt: phạt lũy tiến từ 30s $\rightarrow$ 2 phút $\rightarrow$ 10 phút $\rightarrow$ 24 giờ $\rightarrow$ Đưa vào Blacklist vĩnh viễn.
6. **Layer 6 (Slowloris & Frame Validation):** Kiểm tra lượng byte tối thiểu và thông lượng gói tin.
7. **Layer 7 (Distributed & Subnet Cluster Detection):**
   - Khi phát hiện đợt tấn công từ nhiều IP botnet cùng dải: tự động khóa cả dải `/24` hoặc `/16`.
   - Chế độ Cluster Attack tự động drop các IP lạ trong thời gian đột biến.
8. **Layer 8 (Adaptive Throttling & Surge):** Tự động điều chỉnh trạng thái phòng thủ (`NORMAL` $\rightarrow$ `ELEVATED` $\rightarrow$ `CRITICAL`).
9. **Kernel-Level OS Dropping:**
   - Trên **Windows**: Tự động tạo rule trong `netsh advfirewall` để drop packet tại tầng network driver.
   - Trên **Linux**: Tự động chèn rule vào `iptables` để loại bỏ packet trước khi chạm vào user space.
