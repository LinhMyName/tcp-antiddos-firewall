# 🛡️ High-Performance Anti-DDoS TCP Proxy Firewall

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-blue?style=flat)](https://github.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Defense Layers](https://img.shields.io/badge/Defense%20Layers-8%20Layers-red.svg)](README.md)

Hệ thống **Tường Lửa Kiêm TCP Reverse Proxy Trung Gian** (Anti-DDoS TCP Shield) hiệu năng cao, chuyên dụng bảo vệ Game Server (hoặc các dịch vụ TCP bất kỳ) đặt trên VPS trung gian để gánh đòn tấn công, lọc sạch traffic độc hại và giấu kín IP Server gốc.

Hỗ trợ chạy native đa nền tảng trên cả **Linux VPS** (Ubuntu, Debian, CentOS, Rocky Linux) và **Windows Server**.

---

## 🚀 Sơ Đồ Hoạt Động (Architecture)

```text
[ Người Chơi Game / Traffic Ngoài ]
                 │
                 ▼ (Kết nối vào IP VPS Firewall: Port 13979)
┌────────────────────────────────────────────────────────┐
│  VPS TRUNG GIAN (Chạy Firewall Proxy)                  │
│  - 8 Lớp lọc sâu: SYN Flood, Socket Ngoại, Botnet      │
│  - Chặn O(1) bằng IPSet / Mangle PREROUTING            │
│  - Tự động gán Blacklist thời gian thực & Hot-reload   │
└───────────────────────────┬────────────────────────────┘
                            │ (Chỉ chuyển tiếp lưu lượng SẠCH)
                            ▼
┌────────────────────────────────────────────────────────┐
│  VPS SERVER GAME GỐC (Windows / Linux)                 │
│  - Hoàn toàn vô hình trên Internet                     │
│  - Firewall gốc khóa cổng, chỉ nhận từ VPS Trung Gian  │
└────────────────────────────────────────────────────────┘
```

---

## ⚡ Tính Năng Chính & 8 Lớp Bảo Vệ

1. **Layer 1: Access Control (Whitelist & Blacklist)**
   - Hỗ trợ IP đơn và dải CIDR (`10.0.0.0/8`, `192.168.1.0/24`).
   - Tự động **Hot-reload** danh sách từ file mỗi 60 giây không cần restart server.
2. **Layer 2: Rate Limiting & Connection Tracking**
   - Phân chia hạn ngạch nghiêm ngặt giữa IP ngoài (mặc định 5 conns, 3 conn/s) và IP Whitelist (200 conns, 100 conn/s).
   - Kiểm soát băng thông (bytes/sec) và tần suất gửi gói tin (packets/sec).
3. **Layer 3: Half-Open Connection & SYN Flood Defense**
   - Đặt deadline 3 giây nhận gói tin đầu tiên; tự động drop và phạt điểm các socket kết nối ảo/treo port.
   - Ngăn chặn triệt để tấn công cạn kiệt socket (SYN exhaustion).
4. **Layer 4: 29 Attack Signatures Engine**
   - **Chặn Socket Ngoại (Proxy Botnet):** Tự động phát hiện và khóa SOCKS4, SOCKS4a, SOCKS5, HTTP CONNECT Proxy, Shadowsocks.
   - **Chặn Flood Tool:** LOIC, HOIC, Slowloris, RUDY, MHDDoS, Hammer Head, Xerxes, Tor's Hammer, 0xFF protocol...
   - **Quét Shannon Entropy:** Ngăn chặn các luồng byte ngẫu nhiên rác hoặc uniform byte flood (`0x00`, `0xFF`, `0x41`...).
5. **Layer 5: Behavioral Penalty & Progressive Ban**
   - Tích lũy điểm phạt theo hành vi kết nối ngắn hạn rác, spam kết nối.
   - Khóa lũy tiến tự động: 30s $\rightarrow$ 2 phút $\rightarrow$ 10 phút $\rightarrow$ 24 giờ $\rightarrow$ Ghi vào Blacklist vĩnh viễn.
6. **Layer 6: Slowloris & Frame Throughput Validation**
   - Giám sát thông lượng tối thiểu trên mỗi kết nối, loại bỏ kết nối gửi nhỏ giọt để giữ socket.
7. **Layer 7: Distributed Cluster & Subnet Detection**
   - Phát hiện botnet phân tán; tự động gom cụm và khóa cả dải `/24` hoặc `/16` nếu có nhiều IP cùng dải spam.
8. **Layer 8: Adaptive Throttling & Surge Protection**
   - Tính toán lưu lượng nền theo thời gian thực.
   - Tự động chuyển mode phòng thủ: `NORMAL` $\rightarrow$ `ELEVATED` $\rightarrow$ `CRITICAL` (khi đột biến x3, chỉ cho phép IP Whitelist).
9. **Kernel-Level OS Dropping:**
   - **Linux:** Tự động tạo hash table **`ipset`** và chèn vào `mangle PREROUTING` để drop packet ở tốc độ $O(1)$ ngay tại card mạng.
   - **Windows:** Tự động gọi `netsh advfirewall` để drop ở mức Network Driver.
10. **Tối ưu Game Ping:** Tích hợp `TCP_NODELAY` (vô hiệu hóa Nagle) và `TCPKeepAlive`, giảm thiểu tối đa độ trễ cho game thủ.

---

## 📦 Hướng Dẫn Sử Dụng Nhanh (Quickstart)

Các file chạy sẵn đã được biên dịch sẵn trong thư mục `bin/`.

### 1. Triển khai trên Linux VPS (Ubuntu / Debian / CentOS)

```bash
# 1. Clone repository
git clone https://github.com/LinhMyName/tcp-antiddos-firewall.git
cd tcp-antiddos-firewall/bin

# 2. Chạy script tối ưu hóa Kernel Linux (1-click)
sudo chmod +x optimize-vps.sh firewall-linux-amd64
sudo ./optimize-vps.sh

# 3. Sửa cấu hình config.txt trỏ về server game của bạn
nano config.txt

# 4. Chạy Firewall
sudo ./firewall-linux-amd64
```

#### Chạy dưới dạng Systemd Service (Tự khởi động cùng VPS):
```bash
sudo nano /etc/systemd/system/firewall.service
```
Dán nội dung sau:
```ini
[Unit]
Description=Anti-DDoS TCP Proxy Firewall
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/firewall/bin
ExecStart=/opt/firewall/bin/firewall-linux-amd64 -config /opt/firewall/bin/config.txt
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```
Kích hoạt service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable firewall
sudo systemctl start firewall
```

---

### 2. Triển khai trên Windows Server

1. Tải về hoặc clone repo về máy.
2. Mở thư mục `bin/`, chỉnh sửa file `config.txt` trỏ về IP và Port server game.
3. Chuột phải vào **`firewall.exe`** chọn **Run as administrator** (để cấp quyền cho firewall gọi `netsh advfirewall` drop packet tầng Kernel).

---

## ⚙️ Cấu Hình (`config.txt`)

```ini
# Port firewall lắng nghe trên VPS trung gian (Public-facing)
firewall_host=0.0.0.0
firewall_port=13979

# Địa chỉ & Port của Server Game gốc (Backend Server)
backend_host=103.xxx.xxx.xxx
backend_port=13979

# Giới hạn cho IP ngoài (Chưa tin cậy)
max_conn_per_external_ip=5   # Tối đa 5 kết nối đồng thời từ 1 IP ngoài
max_conn_rate_external=3     # Tối đa 3 kết nối mới/giây từ 1 IP ngoài
max_msgs_per_sec_external=50 # Tối đa 50 gói tin/giây từ 1 IP ngoài

# Giới hạn toàn cục
max_global_conn_rate=500     # Tối đa kết nối mới/giây toàn hệ thống
max_global_active=2000       # Tối đa tổng số kết nối đồng thời

# Chặn & Phạt
penalty_threshold=150        # Tự động chặn khi điểm phạt đạt 150
auto_blacklist_offenses=3    # Đưa vào blacklist vĩnh viễn sau 3 lần tái phạm
kernel_block_enabled=true    # Kích hoạt drop ở tầng Kernel OS

# Tự động nạp lại danh sách
whitelist_reload_sec=60      # Tự động tải lại whitelist.txt mỗi 60 giây
stats_interval_sec=5         # Tần suất in bảng thống kê Dashboard (giây)
```

---

## 🛠️ Biên Dịch Từ Mã Nguồn (Build From Source)

Yêu cầu: Đã cài đặt [Go 1.22+](https://golang.org/dl/).

```bash
# Clone source code
git clone https://github.com/LinhMyName/tcp-antiddos-firewall.git
cd tcp-antiddos-firewall

# Biên dịch bản chạy cho Windows (.exe)
go build -ldflags="-s -w" -o bin/firewall.exe ./cmd/firewall

# Biên dịch bản chạy cho Linux VPS (ELF 64-bit)
# (Trên Linux):
go build -ldflags="-s -w" -o bin/firewall-linux-amd64 ./cmd/firewall

# (Hoặc Cross-compile cho Linux ngay trên Windows):
# Windows CMD:
set GOOS=linux&& set GOARCH=amd64&& go build -ldflags="-s -w" -o bin/firewall-linux-amd64 ./cmd/firewall
# Windows PowerShell:
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -ldflags="-s -w" -o bin/firewall-linux-amd64 ./cmd/firewall
```

---

## 🧪 Chạy Kiểm Thử (Unit & Integration Tests)

```bash
go test -v ./...
```

---

## 📄 Giấy Phép (License)
Dự án được phân phối dưới giấy phép [MIT License](LICENSE). Bạn hoàn toàn có thể tự do sử dụng, chỉnh sửa và triển khai cho các dự án cá nhân hoặc thương mại.
