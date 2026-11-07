# HƯỚNG DẪN TRIỂN KHAI ANTI-DDOS TCP FIREWALL v3.8
*(Chạy đa nền tảng: Linux VPS & Windows — Tích hợp Web Control Plane & GeoIP IN/OUT)*

Dự án này là hệ thống **Firewall kiêm TCP Reverse Proxy trung gian** chuyên dụng để đặt trên VPS chặn trước Server Game gốc, có khả năng gánh tải, phát hiện và phân tán các đợt tấn công DDoS TCP Flood với **9 lớp bảo vệ chuyên sâu**, **Chặn Quốc Tế (GeoIP IN/OUT)** và **Giao diện Web Hacker Control Plane** trực quan.

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

### 2.1. Cấu hình đẩy IP gốc của người chơi về Server Backend (PROXY Protocol)

Mặc định khi qua TCP Reverse Proxy, Server Game gốc sẽ chỉ thấy IP của VPS Firewall kết nối tới. Để đẩy IP thật của Client/người chơi về Server Game gốc, cấu hình tham số sau trong `config.txt`:

```ini
# Giá trị: off (mặc định), v1 (Text), v2 (Binary)
proxy_protocol=v1
```

- **`proxy_protocol=v1`**: Gửi header text theo chuẩn HAProxy PROXY Protocol v1 ngay đầu kết nối:
  `PROXY TCP4 <Client_IP> <Firewall_IP> <Client_Port> <Firewall_Port>\r\n`
- **`proxy_protocol=v2`**: Gửi header binary nhị phân theo chuẩn HAProxy PROXY Protocol v2 (hiệu năng cao, 28 bytes).

#### 🛠️ Hướng dẫn phía Server Game gốc nhận diện IP thật:

**Cách 1: Nếu Server Game hỗ trợ sẵn PROXY Protocol (Minecraft Velocity / BungeeCord / Paper):**
- Mở file cấu hình game server (ví dụ `velocity.toml`, `config.yml`, hoặc `paper.yml`), tìm mục:
  ```yaml
  proxy-protocol: true
  ```
- Khởi động lại server game, server sẽ tự động nhận diện IP gốc của người chơi.

**Cách 2: Nếu Server Game đứng sau Nginx Stream:**
```nginx
stream {
    server {
        listen 14445 proxy_protocol;
        proxy_pass 127.0.0.1:24445; # Forward vào Game Server nội bộ
    }
}
```

**Cách 3: Nếu Server Game tự lập trình (C++, C#, Java, Go, NodeJS, Python):**
Khi nhận kết nối socket mới, server đọc chuỗi text đầu tiên đến ký tự `\r\n`.
Nếu bắt đầu bằng `PROXY TCP4 `, tách chuỗi theo khoảng trắng: phần tử thứ 3 là IP thật!

*Mẫu code C# Socket:*
```csharp
byte[] buf = new byte[256];
int read = clientSocket.Receive(buf, SocketFlags.Peek);
string header = Encoding.ASCII.GetString(buf, 0, read);
if (header.StartsWith("PROXY TCP4 ")) {
    // Đọc chính thức để nuốt header ra khỏi luồng
    int endIdx = header.IndexOf("\r\n") + 2;
    clientSocket.Receive(new byte[endIdx]);
    
    string[] parts = header.Substring(0, endIdx - 2).Split(' ');
    string realClientIP = parts[2];
    Console.WriteLine($"[INFO] Player Real IP: {realClientIP}");
}
```

*Mẫu code Node.js:*
```javascript
const net = require('net');
const server = net.createServer((socket) => {
    socket.once('data', (data) => {
        const text = data.toString('utf8');
        if (text.startsWith('PROXY TCP4 ')) {
            const lineEnd = text.indexOf('\r\n');
            const parts = text.substring(0, lineEnd).split(' ');
            const realIP = parts[2];
            console.log('Player Real IP:', realIP);
            
            // Dữ liệu game còn lại sau header (nếu có):
            const gameData = data.subarray(lineEnd + 2);
            if (gameData.length > 0) handleGamePacket(socket, gameData);
        }
    });
});
```

**Cách 4: Dành cho Server Game binary đóng (không sửa được source code) trên Linux:**
- Sử dụng tool **`mmproxy`** của Cloudflare đặt trên Server Game gốc.
- `mmproxy` lắng nghe gói PROXY Protocol từ Firewall VPS, sau đó sử dụng Linux `TPROXY` chuyển tiếp vào cổng game nội bộ và gán thẳng IP thật vào socket hệ điều hành.

### 2.2. Cấu hình Chặn Quốc Tế - Chỉ Cho Phép Việt Nam hoặc Một Vài Quốc Gia (Only IN & OUT)

Tính năng **GeoIP International Blocker** cho phép khóa toàn bộ kết nối Quốc tế (cả chiều **IN** và chiều **OUT**), chỉ cho phép lưu lượng từ **Việt Nam (`VN`)** hoặc danh sách các quốc gia chỉ định (`VN,SG,JP,KR...`).

- **Tích hợp sẵn Offline 1,666 dải IP Việt Nam (VNNIC/APNIC)** ngay trong file thực thi (hoạt động 100% offline kể cả khi VPS đã khóa đường truyền quốc tế).
- **Tự động tải & cache** dải IP của bất kỳ quốc gia nào khác vào thư mục `geoip/<mã_quốc_gia>.zone`.

Mở `config.txt` và cấu hình:
```ini
# Bật tính năng lọc theo Quốc gia
geoip_enabled=true

# Danh sách quốc gia ĐƯỢC PHÉP (Mã ISO 2 ký tự, cách nhau bởi dấu phẩy):
# - Chỉ Việt Nam: VN
# - Việt Nam + Singapore + Nhật + Hàn: VN,SG,JP,KR
geoip_allowed_countries=VN

# Hoặc chặn cụ thể một số quốc gia (tùy chọn, ví dụ: CN,RU)
geoip_blocked_countries=

# Hướng kiểm soát:
# - both : Only IN & OUT cho các quốc gia được phép (Chặn quốc tế cả chiều VÀO và RA)
# - in   : Chỉ lọc chiều VÀO (Inbound)
# - out  : Chỉ lọc chiều RA (Outbound)
geoip_direction=both

# Chặn cứng ở tầng Kernel OS trên Linux bằng ipset (O(1) tại PREROUTING & OUTPUT)
geoip_kernel_enforce=false
```

Hoặc chạy nhanh bằng cờ lệnh CLI:
```bash
# Chỉ cho phép Việt Nam cả IN và OUT:
./firewall.exe -geoip true -countries VN -geoip-dir both

# Cho phép Việt Nam, Singapore, Nhật Bản:
./firewall.exe -countries VN,SG,JP -geoip-dir both
```

### 2.3. Giao Diện Web Hacker Control Plane & Cấp Endpoint Nối Server Gốc (`http://<IP_VPS>:8080`)

Từ phiên bản **v3.8**, Firewall tích hợp sẵn trang web điều khiển **AEGIS-X // CYBER DEFENSE MATRIX** nhúng trực tiếp trong file chạy (không cần cài thêm Nginx/Apache/NodeJS).

Mặc định khi khởi động, Web Dashboard tự động mở tại cổng **`8080`**:
- Trên máy local: Mở trình duyệt vào `http://localhost:8080`
- Trên VPS: Mở trình duyệt vào `http://<IP_VPS_FIREWALL>:8080`
- Cấu hình trong `config.txt`:
  ```ini
  web_enabled=true
  web_host=0.0.0.0
  web_port=8080
  web_public_domain=anti.tenmiencuaban.vn
  ```

#### Các tính năng trên Web Control Plane:
1. **Radar Toàn Cầu & Biểu Đồ Lưu Lượng 180 Giây (`01 TELEMETRY & RADAR`):**
   - **Global Edge Topology Radar:** Hiển thị trực quan bằng đồ họa Canvas các luồng kết nối từ quốc tế (`US`, `EU`, `RU`, `CN`, `JP`, `SG`) và nội địa (`HAN`, `SGN`) đi vào lõi Firewall, tự động nổ vòng chắn đỏ khi chặn IP quốc tế hoặc DDoS và chuyển tiếp luồng sạch (màu xanh Cyan) tới Server Gốc.
   - **180-Second Oscilloscope:** Biểu đồ sóng thời gian thực thống kê băng thông `Ingress (RX)` và `Egress (TX)` với nút chuyển đổi đơn vị **`Mbps` / `Gbps` / `PPS (Gói/giây)`**.
   - **Origin $\rightarrow$ Firewall Endpoint Lookup:** Nhập `IP Gốc` + `Port Gốc` để tra cứu nhanh địa chỉ Endpoint Firewall đang bảo vệ và copy 1 chạm.
2. **Cấp IP/Port Server Gốc & Nối Endpoint Firewall (`02 ORIGIN ⇄ FW ENDPOINTS`):**
   - Cho phép thêm không giới hạn các máy chủ gốc (`Origin IP` + `Origin Port`, ví dụ `103.x.x.x:14445`).
   - Tự động cấp Port Firewall (`20001`, `20002`...) hoặc nhập Port tùy chọn (`14445`, `9999`...) để tạo ra địa chỉ Endpoint (`domain:listen_port`) cấp cho Client Game.
   - Mỗi Route có công tắc **ON/OFF** riêng, nút **PING** đo độ trễ TCP thực tế tới máy chủ gốc (`ms`), nút **EDIT** và **COPY ENDPOINT**.
3. **Bảng Công Tắc Bật/Tắt 9 Lớp Phòng Thủ (`03 DEFENSE ON/OFF MATRIX`):**
   - Bật/tắt tức thì (Hot-Reload, tự lưu vào `config.txt`) cho:
     - `GeoIP International Blocker (VN Only / Multi-Country)`
     - `Linux Kernel ipset GeoIP Enforcement`
     - `OS Kernel Packet Dropper (iptables / netsh)`
     - `29-Pattern L7 Attack Signature Engine`
     - `Half-Open SYN & Handshake Shield`
     - `Slowloris & Short-Lived Flood Detector`
     - `Botnet /24 & /16 Subnet Auto-Ban`
     - `Dynamic Surge Auto-Elevation`
     - `Emergency Whitelist-Only Lockdown`
4. **Luồng Sự Kiện Tấn Công & Quản Lý ACL (`04 THREAT STREAM & ACL`):**
   - Theo dõi trực tiếp từng IP bị chặn kèm lý do, bấm **BAN IP** 1 chạm hoặc thêm/xóa trực tiếp **Whitelist / Blacklist** ngay trên giao diện web.

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
