# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản:
  Gitleaks v8.30.1 (chạy qua binary `gitleaks` được ghim phiên bản).

- Commit chứa token giả:
  Commit `1bdd849` (đầy đủ: `1bdd849922156c868a5ee9293d68f5b72e242d2c`).

- File, rule và kết quả quét lịch sử:
  - File: `lab-fake-secret.txt`, dòng 1.
  - Rule ID: `lab24-synthetic-token`.
  - Kết quả quét lịch sử bằng lệnh `gitleaks git --config .gitleaks.toml --redact --verbose .`: Phát hiện 1 leak do token giả dạng synthetic demo cài sẵn trong lịch sử repo.

- Kết quả quét file hiện tại:
  Quét thư mục làm việc hiện tại bằng lệnh `gitleaks dir --config .gitleaks.toml .`: Kết quả sạch hoàn toàn (`no leaks found`, 0 leaks), do file `lab-fake-secret.txt` đã được xóa trong commit tiếp theo.

- Nếu đây là credential thật, cần xử lý thế nào:
  Cần ngay lập tức thu hồi (revoke) và rotate credential đó tại nhà cung cấp dịch vụ / hệ thống quản lý danh tính (IAM/IdP). Cấp phát token mới, cập nhật secret store an toàn và tiến hành rà soát audit log để phát hiện các truy cập bất thường trong thời gian token bị lộ.

- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
  - Xóa file khỏi HEAD chỉ làm file biến mất ở commit hiện tại; toàn bộ nội dung và credential vẫn tồn tại vĩnh viễn trong Git commit history (DAG) mà bất kỳ ai clone repository cũng có thể trích xuất ra.
  - Pin dependency bằng hash lock (`requirements.lock`) và pre-commit hook chỉ ngăn chặn rủi ro supply chain và ngăn chặn việc commit lộ lọt mới trong tương lai; chúng không thể hủy bỏ hay làm mất hiệu lực quyền hạn của một credential đã lọt ra ngoài.
  - Một secret khi đã lộ ra ngoài bắt buộc phải được rotate / thu hồi tại nguồn cung cấp dịch vụ, không có biện pháp trên source code nào thay thế được việc này.
