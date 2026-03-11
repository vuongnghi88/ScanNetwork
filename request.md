# ScanNetwork — Request & Requirements Log
<!-- Mỗi phiên làm việc được append vào đây -->

---

## 📅 Phiên 1 — 2026-03-11

### Yêu cầu ban đầu (Core Requirements)

#### 1. Mục tiêu cốt lõi
- **Môi trường thử nghiệm**: Laptop kết nối Wi-Fi Guest đóng vai kẻ tấn công.
- **Kịch bản chính**: Kiểm tra VLAN Hopping/Routing từ mạng Guest → Internal/Server/Admin.
- **Hình thức quản trị**: Giao diện Web Local thay cho CLI.

#### 2. Kiến trúc hệ thống
- **Backend**: Python + Flask
- **Công cụ quét**: Nmap (python-nmap + subprocess)
- **Frontend**: HTML, Bootstrap, JavaScript/AJAX
- **Xử lý tác vụ**: Background threading (Python threading + queue)
- **Lưu trữ**: SQLite — lưu Baseline và lịch sử quét

#### 3. Chức năng chính

**A. Quét & Khám phá**
- Host Discovery: Xác định thiết bị online trong dải Guest, thăm dò dải IP nội bộ
- Port Scanning: Tìm cổng mở (SSH, RDP, SMB, Database, Web Admin)
- Service Identification: Banner grabbing, lấy thông tin phiên bản dịch vụ

**B. Nhận diện thiết bị**
- MAC Vendor: 3 cặp số đầu → hãng sản xuất (Hikvision→Camera, Cisco→Switch…)
- Port đặc trưng: Cổng 554→Camera, Cổng 8008→Smart TV…
- OS Detection: Nmap fingerprint → Windows/Linux/Embedded

**C. Kiểm soát & Cảnh báo**
- Kiểm tra phân đoạn mạng: Phát hiện "lỗ thủng" Guest→Local
- So sánh sai lệch (Diff): Phát hiện IP lạ, cổng mới mở
- Bộ quy tắc: Gán nhãn thiết bị (Camera, TV, PC, Switch) vào Database

#### 4. Nguyên tắc an toàn
- Sanitize Input: Chặn Command Injection ở ô nhập IP
- Phân quyền: Không chạy Web Server bằng quyền root
- Impact Control: Giới hạn tốc độ quét (T3), không gây nghẽn mạng

---

### Bổ sung phiên 1 — 07:45

#### Wildcard IP Format
Hỗ trợ cú pháp wildcard khi nhập IP target:
- `192.168.1.*` → quét từ `192.168.1.1` đến `192.168.1.254`
- `192.168.*.*` → quét từ `192.168.1.1` đến `192.168.254.254`
- Tự động chuyển đổi sang CIDR/range trước khi đưa vào Nmap

#### Network List Configuration
Thêm 3 danh sách mạng cấu hình sẵn trong `config.py` và UI:
- **Guest List**: Dải IP của mạng khách (ví dụ: `192.168.1.0/24`)
- **Server List**: Dải IP của Server (ví dụ: `10.10.10.0/24`)
- **Local/Internal List**: Dải IP nội bộ (ví dụ: `172.16.0.0/16`)

Mục đích: Khi chọn "Guest" trong UI → tự động điền target từ config, giúp quét đúng vùng mạng và thăm dò đúng mục tiêu VLAN hop.
- Nmap scanner integration with python-nmap
- Background worker logic to keep UI unblocked
- REST API implementation
- Web frontend with standard bootstrap and dark UI
- Added Network lists (`config.py`) and quick presets to frontend
- Added Wildcard IP processing allowing e.g. `192.168.1.*` to automatically expand to `192.168.1.0/24` for quick host scanning
- Fixed lazy-loading of Nmap to prevent Flask crashes when binary isn't perfectly configured
- Added Baseline diffing UI and `/api/stats` dashboard data.
- Created `run_project.bat` helper to automate library installation and server startup.

---
---

### Bổ sung phiên 2 — 10:40
#### Cải tiến script chạy dự án (Runner Script Enhancement)
- Bổ sung cơ chế kiểm tra cổng mạng (Port Check): Trước khi khởi động, kiểm tra xem cổng `5000` (mặc định của Flask) có đang bị chiếm dụng hay không.
- Tự động Restart: Nếu phát hiện ứng dụng đang chạy, script sẽ tự động đóng (kill process) và khởi động lại phiên bản mới nhất.
- Mục đích: Tránh lỗi "Port already in use" và đảm bảo nhà phát triển luôn chạy code mới nhất mà không cần thao tác thủ công để tắt server cũ.
