# ScanNetwork — Công cụ quét an ninh mạng nội bộ

ScanNetwork là một ứng dụng web mạnh mẽ giúp bạn giám sát, quét và phân tích an ninh trong mạng cục bộ (LAN). Công cụ này tích hợp Nmap để cung cấp các tính năng từ quét thiết bị cơ bản đến phát hiện lỗ hổng chuyên sâu.

## Các Tính Năng Chính
- **Quét thiết bị (Host Discovery)**: Nhanh chóng tìm thấy tất cả các thiết bị đang hoạt động trong mạng của bạn.
- **Quét Cổng & Dịch vụ**: Xác định các cổng đang mở và các dịch vụ (HTTP, SSH, Database...) đang chạy trên từng thiết bị.
- **Nhận diện Hệ điều hành**: Dự đoán hệ điều hành của máy đích (Windows, Linux, macOS...).
- **Danh sách Giám sát (Monitored Devices)**: Quản lý danh sách các thiết bị quan trọng với thông tin Hãng sản xuất và Mã hàng để theo dõi biến động.
- **Chế độ Ẩn mình (Stealth Scan)**: Sử dụng các kỹ thuật như phân mảnh gói tin và xáo trộn máy đích để tránh bị Firewall chặn.
- **Quét Lỗ hổng (NSE Vuln)**: Tự động kiểm tra các lỗi bảo mật phổ biến (CVE) trên các dịch vụ đang chạy.
- **Hệ thống Cảnh báo**: Tự động thông báo khi phát hiện các cổng nguy hiểm hoặc thay đổi bất thường (VLAN Hop...).
- **Lịch sử & Dữ liệu mẫu**: Lưu trữ kết quả các lần quét để so sánh và thiết lập dữ liệu mẫu (Baseline).

## Hướng Dẫn Sử Dụng
1. **Quét mạng**:
   - Truy cập trang **Quét mạng**.
   - Nhập mục tiêu (IP đơn, dải IP hoặc CIDR như `192.168.1.0/24`).
   - Chọn loại quét (Khám phá nhanh hoặc Quét đầy đủ).
   - (Tùy chọn) Mở **Cấu hình Nâng cao** để chọn tốc độ (Timing) hoặc bật Stealth Mode/Quét lỗ hổng.
   - Nhấn **Bắt đầu** để thực hiện.
2. **Quản lý thiết bị**:
   - Xem danh sách tất cả các thiết bị đã phát hiện tại trang **Thiết bị**.
   - Thêm các thiết bị quan trọng vào **Thiết bị giám sát** để theo dõi chi tiết.
3. **Theo dõi cảnh báo**:
   - Kiểm tra tab **Cảnh báo** để xem các nguy cơ an ninh được hệ thống tự động phân loại.

## Yêu Cầu Hệ Thống
- Python 3.8+
- Nmap (đã cài đặt và có trong PATH)

---
Hỗ trợ: [@trunguyen](https://t.me/truinguyen)
