#!/bin/bash
# ============================================================
# SCRIPT TỐI ƯU HÓA LINUX VPS CHỐNG DDOS TCP FLOOD & GIẢM PING
# Dành cho VPS trung gian làm Firewall Game Server
# ============================================================

set -e

if [ "$EUID" -ne 0 ]; then
  echo "[LỖI] Vui lòng chạy script này với quyền root: sudo ./optimize-vps.sh"
  exit 1
fi

echo "============================================================"
echo "  BẮT ĐẦU TỐI ƯU HÓA KERNEL & HỆ THỐNG LINUX CHO FIREWALL"
echo "============================================================"

# 1. Cài đặt IPSet (Hỗ trợ tra cứu và drop IP O(1) siêu tốc)
echo "[1/4] Kiểm tra và cài đặt ipset..."
if ! command -v ipset &> /dev/null; then
    if command -v apt-get &> /dev/null; then
        apt-get update -y && apt-get install -y ipset
    elif command -v yum &> /dev/null; then
        yum install -y ipset
    elif command -v dnf &> /dev/null; then
        dnf install -y ipset
    fi
fi
echo "      -> IPSet: Đã sẵn sàng."

# 2. Tối ưu hóa Sysctl Chống TCP SYN Flood & Connection Exhaustion
echo "[2/4] Cấu hình Kernel Linux chống SYN Flood (sysctl)..."
cat << 'EOF' > /etc/sysctl.d/99-antiddos-game.conf
# Kích hoạt SYN Cookie chống tràn hàng đợi SYN Flood
net.ipv4.tcp_syncookies = 1

# Tăng dung lượng hàng đợi SYN Backlog (mặc định chỉ 512-1024)
net.ipv4.tcp_max_syn_backlog = 65536

# Tăng giới hạn số lượng kết nối đang chờ accept()
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536

# Giảm số lần retry gửi lại gói SYN-ACK (hủy kết nối ma sau 3 giây)
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

# Giải phóng nhanh socket ở trạng thái FIN_WAIT
net.ipv4.tcp_fin_timeout = 10

# Tái sử dụng socket TIME_WAIT cho kết nối mới
net.ipv4.tcp_tw_reuse = 1

# Bật bảo vệ chống IP Spoofing (Reverse Path Filtering)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Chống Smurf Attack (bỏ qua broadcast echo)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Mở rộng dải port cục bộ cho kết nối ra ngoài
net.ipv4.ip_local_port_range = 1024 65535

# Tối ưu bộ đệm TCP (Buffer size)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Bật thuật toán nghẽn TCP BBR (nếu kernel hỗ trợ) để tối ưu ping game
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

sysctl --system > /dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-antiddos-game.conf
echo "      -> Cấu hình Kernel chống SYN flood: Hoàn tất."

# 3. Tăng giới hạn số lượng file/socket mở đồng thời (File Descriptors)
echo "[3/4] Tăng giới hạn File Descriptors (cho phép gánh > 100,000 kết nối)..."
cat << 'EOF' >> /etc/security/limits.conf
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
ulimit -n 1048576 || true
echo "      -> Giới hạn Socket: 1,048,576."

# 4. Tạo sẵn IPSet Chain
echo "[4/4] Khởi tạo bộ băm IPSet chống DDoS..."
ipset create antiddos_blacklist hash:ip hashsize 65536 maxelem 1000000 -exist
ipset create antiddos_subnets hash:net hashsize 4096 maxelem 1000000 -exist
iptables -t mangle -C PREROUTING -m set --match-set antiddos_blacklist src -j DROP 2>/dev/null || iptables -t mangle -I PREROUTING 1 -m set --match-set antiddos_blacklist src -j DROP
iptables -t mangle -C PREROUTING -m set --match-set antiddos_subnets src -j DROP 2>/dev/null || iptables -t mangle -I PREROUTING 1 -m set --match-set antiddos_subnets src -j DROP
echo "      -> IPSet Mangle Chain: Sẵn sàng."

echo "============================================================"
echo "  [THÀNH CÔNG] VPS TRUNG GIAN ĐÃ ĐƯỢC TỐI ƯU HOÀN TOÀN!"
echo "  Bây giờ bạn có thể khởi động firewall:"
echo "  sudo ./firewall-linux-amd64"
echo "============================================================"
