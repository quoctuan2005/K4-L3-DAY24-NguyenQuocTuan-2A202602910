# DPIA-lite — điền trong checkpoint 5

1. Loại dữ liệu và phân loại:
- Dữ liệu nội bộ (Internal): Nội dung yêu cầu hỗ trợ khách hàng và văn bản ticket trong `corpus/` (`ticket-001.md` đến `ticket-040.md`, cùng các lure 901–904b), thông điệp truy vấn của nhân viên.
- Dữ liệu cá nhân nhạy cảm (Restricted): Hồ sơ khách hàng trong `data/customers.json` chứa các trường PII gồm Số CCCD (12 chữ số), Số điện thoại (10 chữ số), Số tài khoản ngân hàng (8–16 chữ số), Địa chỉ Email và danh sách ticket liên quan.

2. Mục đích xử lý và principal:
- Mục đích (Purpose): `summarize-tickets` (tổng hợp thông tin sự vụ hỗ trợ), `support-reply` (tra soát và phản hồi khách hàng), `privacy-audit` (kiểm toán tuân thủ bảo vệ dữ liệu).
- Danh tính ủy quyền (Principal):
  - `support_l1`: Chỉ được cấp quyền `search_docs` đối với tài liệu nội bộ; bị chặn tuyệt đối quyền truy cập `read_customer` chứa dữ liệu phân loại restricted.
  - `dpo`: Được quyền `search_docs` và `read_customer` phục vụ đối soát nghiệp vụ hợp lệ và kiểm toán quyền riêng tư; không được cấp quyền egress (`http_post`).

3. Dữ liệu đi qua những run/tool nào, endpoint nào:
- Run A (`lab24-agent/run-a`): Tiếp nhận truy vấn người dùng, gọi `search_docs` để đọc kho `corpus/`. Run A chỉ trích xuất danh sách số nguyên `ticket_ids` từ tên file (ví dụ `ticket-007.md` -> 7) và chuyển sang Run B. Toàn bộ free text từ tài liệu không tin cậy bị cô lập tại Run A.
- Run B (`lab24-agent/run-b`): Tiếp nhận danh sách `ticket_ids`, tra cứu chéo với trường `related_tickets` trong `customers.json` để xác định đúng khách hàng hợp lệ. Gọi `read_customer` để đọc hồ sơ khi được Policy PEP phê duyệt.
- Endpoint egress: Chỉ thị `http_post` tới endpoint `http://127.0.0.1:10024/reconcile` bị chặn đứng tại Policy PEP do vi phạm quy tắc kết hợp dữ liệu restricted với kênh mạng bên ngoài. Không có byte PII nào rời khỏi máy trạm.

4. Bằng chứng deny/allow và giới hạn của mock:
- Bằng chứng thực tế:
  - `reports/attack-before.log` lưu giữ bằng chứng rò rỉ dữ liệu của `KH-000999` trước khi kiểm soát.
  - `reports/attack-after.log` có kích thước 0 byte, chứng minh việc exfiltration ra sink đã bị chặn triệt để.
  - `reports/ledger.jsonl` có đầy đủ các bản ghi audit với `decision: "deny"` cho `http_post` và `read_customer` (với `support_l1`), chuỗi hash SHA-256 xác minh hợp lệ 100%.
  - Bộ kiểm thử tự động `pytest tests/ -q` đạt 33/33 test case passed.
- Giới hạn của mock:
  - Sử dụng Mock LLM dựa trên bộ marker xác định để đảm bảo tính tái lập và chấm điểm khách quan. Hệ thống thực tế cần áp dụng LLM Guardrails / Prompt Shield đa tầng để phòng chống injection zero-day.
  - Cờ `--as` đóng vai trò mô phỏng phân quyền OBO trong khuôn khổ bài lab; production yêu cầu tích hợp Identity Provider (OIDC / SPIFFE / mTLS / OAuth 2.0 Token Exchange RFC 8693) đầy đủ.
