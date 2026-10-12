# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
Chưa có. Trong `agent/loop.py:_naive_loop()` (dòng 27–55), hàm chỉ nhận `message` và `llm`, không hề khởi tạo hay truyền bất kỳ định danh nào như `run_id`, `agent_id`, hay `principal_id` (OBO context). Mọi lần chạy đều vô danh và không phân biệt được phiên làm việc.

2. Ai cho phép `http_post`? Dẫn file/hàm:
Không có cơ chế kiểm soát hay Policy Enforcement Point (PEP) nào cấp phép. Trong `agent/loop.py:_naive_loop()` (dòng 44), lệnh `tools.http_post()` được gọi trực tiếp và vô điều kiện khi tìm thấy chỉ thị injection (`if injected is not None`). Quyền thực thi hoàn toàn bị chiếm đoạt và chỉ định bởi nội dung do kẻ tấn công cài cắm trong tài liệu.

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
Phía agent hoàn toàn không có audit ledger hay nhật ký lưu trữ để chứng minh việc rò rỉ. Bằng chứng duy nhất nằm ở phía bên nhận (sink server) tại file `reports/sink.log`, do hàm `sink/sink.py:make_handler()` (dòng 46–47) thụ động ghi lại các request POST đến endpoint `127.0.0.1:10024`.
