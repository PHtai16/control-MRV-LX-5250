# MRV LX-5250 — Console Server & PDU Manager

> **Python GUI quản trị thiết bị MRV LX-5250 qua giao thức Telnet**  
> Stack: Python 3.10+ · Tkinter · raw socket · RFC 854 IAC · threading · stdlib only

---

## Mục lục

- [Tổng quan](#tổng-quan)
- [Yêu cầu hệ thống](#yêu-cầu-hệ-thống)
- [Cài đặt & Khởi chạy](#cài-đặt--khởi-chạy)
- [Kiến trúc hệ thống](#kiến-trúc-hệ-thống)
- [Cấu trúc file](#cấu-trúc-file)
- [Giao diện & Tính năng](#giao-diện--tính-năng)
- [Tham chiếu lệnh MRV LX-5250](#tham-chiếu-lệnh-mrv-lx-5250)
- [Bảo mật (Blue Team Notes)](#bảo-mật-blue-team-notes)
- [Xử lý sự cố](#xử-lý-sự-cố)
- [Ghi chú kỹ thuật — Vấn đề IAC](#ghi-chú-kỹ-thuật--vấn-đề-iac)

---

## Tổng quan

Ứng dụng GUI viết bằng Python thuần (chỉ dùng stdlib) để quản trị từ xa thiết bị **MRV LX-5250 Switched PDU / Console Server** thông qua giao thức **Telnet (TCP port 23)**.

### Thiết bị được hỗ trợ

| Model | Firmware | Giao thức | Port mặc định |
|---|---|---|---|
| MRV LX-5250 | v5.3f | Telnet (RFC 854) | 23 |

### Tính năng chính

- ✅ Xác thực tự động (state machine: `Username →  Password →  LX:`)
- ✅ Xử lý IAC negotiation thủ công (RFC 854) — tương thích Python 3.13+
- ✅ 5-tab UI với `ttk.Notebook`
- ✅ Điều khiển outlet (ON / OFF / REBOOT) theo Port ID 1–8
- ✅ Giám sát sức khỏe hệ thống (STATUS, ISTAT, ENVMON, VERSION)
- ✅ Command Builder phân cấp (LIST, SHOW, SET, CREATE, DELETE, PING)
- ✅ Raw Terminal tự do
- ✅ Terminal output real-time (nền đen, chữ xanh)
- ✅ Xác nhận trước khi thực thi lệnh phá hủy (OFF, DELETE, REBOOT)
- ✅ Toàn bộ I/O mạng chạy trên luồng phụ — UI không bao giờ bị đóng băng

---

## Yêu cầu hệ thống

| Yêu cầu | Chi tiết |
|---|---|
| Python | **3.10 trở lên** (test trên 3.13, 3.14) |
| OS | Windows, Linux, macOS |
| Thư viện ngoài | **Không có** — chỉ dùng stdlib |
| Kết nối mạng | TCP/IP tới thiết bị MRV, port 23 |
| Quyền | Không cần quyền admin |

> ⚠️ `telnetlib` bị **xoá hoàn toàn từ Python 3.13**. Dự án này tự implement
> RFC 854 IAC negotiation qua raw socket nên hoạt động bình thường trên
> Python 3.13+ mà không cần cài thêm gì.

---

## Cài đặt & Khởi chạy

```bash
# 1. Clone hoặc copy folder về máy
cd mrv_lx5250_manager/

# 2. (Tuỳ chọn) Tạo virtual environment
python -m venv .venv
.venv\Scripts\activate      # Windows
source .venv/bin/activate   # Linux/macOS

# 3. Chạy ứng dụng — không cần pip install gì cả
python gui_main.py
```

### Đăng nhập nhanh

| Field | Giá trị mặc định |
|---|---|
| Device IP | `192.168.1.252` |
| Port | `23` |
| Username | `Admn` |
| Password | *(nhập theo config thiết bị)* |

---

## Kiến trúc hệ thống

```
┌─────────────────────────────────────────────────────────────────────┐
│                         gui_main.py                                 │
│                                                                     │
│  ┌───────────────┐   queue.Queue    ┌──────────────────────────┐   │
│  │  Main Thread  │ ◄─────────────── │   Worker Threads (daemon)│   │
│  │  Tkinter loop │  root.after()    │                          │   │
│  │  @60 Hz poll  │                  │  mrv-connect  (blocking) │   │
│  └──────┬────────┘                  │  mrv-reader   (loop)     │   │
│         │ calls                     │  mrv-send-*   (one-shot) │   │
│         ▼                           └─────────┬────────────────┘   │
│  ┌──────────────┐                             │ calls              │
│  │  MRVApp UI   │                             ▼                    │
│  │  (Tkinter)   │              ┌──────────────────────────────┐    │
│  └──────────────┘              │         mrv_backend.py       │    │
│                                │                              │    │
└────────────────────────────────│  MRVBackend                  │────┘
                                 │  ├── connect()               │
                                 │  ├── send_command()          │
                                 │  ├── disconnect()            │
                                 │  └── read_loop()             │
                                 │                              │
                                 │  _TelnetIAC (RFC 854)        │
                                 │  ├── _parse_iac()            │
                                 │  ├── read_until_any()        │
                                 │  └── write()                 │
                                 └──────────────┬───────────────┘
                                                │ raw TCP socket
                                                ▼
                                    ┌─────────────────────┐
                                    │  MRV LX-5250 Device │
                                    │  192.168.1.252:23   │
                                    └─────────────────────┘
```

### Threading Model

```
Main thread      Worker threads (daemon)
    │                    │
    │  ─── connect() ──► │  mrv-connect
    │                    │    ├─ TCP handshake
    │                    │    ├─ IAC negotiation
    │                    │    └─ Auth state machine
    │  ◄── queue ──────  │       Username → Password → LX:
    │                    │
    │  ─── on auth OK ─► │  mrv-reader  (persistent)
    │                    │    └─ read_loop() until disconnect
    │  ◄── queue ──────  │
    │                    │
    │  ─── send btn ───► │  mrv-send (short-lived, per command)
    │  ◄── queue ──────  │
```

---

## Cấu trúc file

```
mrv_lx5250_manager/
│
├── gui_main.py          # Entry point — giao diện Tkinter 5 tab
├── mrv_backend.py       # Backend mạng — socket, IAC, state machine
├── mrv_lx5250_gui.py    # (Legacy) Single-file prototype — không dùng nữa
├── mrv_gui.log          # Log file tự sinh khi chạy
└── README.md            # Tài liệu này
```

### `mrv_backend.py` — Public API

```python
from mrv_backend import MRVBackend, MRVAuthError, MRVConnectionError, MRVCommandError

backend = MRVBackend()
backend.connect(host, port, username, password, on_data_callback)  # blocking
backend.send_command("STATUS")
backend.read_loop(on_data_callback, on_disconnect_callback)        # blocking loop
backend.disconnect()

backend.is_connected     # bool
backend.is_authenticated # bool
```

---

## Giao diện & Tính năng

### Tab 1 — Connection

| Control | Mô tả |
|---|---|
| Device IP | IP của MRV LX-5250 |
| Port | TCP port Telnet (mặc định 23) |
| Username | Tên đăng nhập |
| Password | Mật khẩu (hiển thị `***`) |
| **Connect** | Bắt đầu kết nối và xác thực |
| **Disconnect** | Ngắt kết nối an toàn |
| Status label | Hiển thị trạng thái realtime |

### Tab 2 — Port Control

Điều khiển nguồn các outlet (cổng PDU) theo Port ID.

| Nút | Lệnh gửi | Mô tả |
|---|---|---|
| **ON** | `ON <N>\r\n` | Cấp nguồn outlet N |
| **OFF** | `OFF <N>\r\n` | Ngắt nguồn outlet N *(xác nhận)* |
| **REBOOT** | `REBOOT <N>\r\n` | Power-cycle outlet N *(xác nhận)* |
| **CONNECT** | `CONNECT <N>\r\n` | Reverse Telnet tới thiết bị tại outlet N |

> **Validation:** Port ID chỉ chấp nhận số nguyên 1–8. Ký tự lạ bị chặn ngay tại widget, không bao giờ xuống socket.

### Tab 3 — System Health

Truy vấn trạng thái hệ thống (không cần tham số):

| Nút | Mô tả |
|---|---|
| **STATUS** | Danh sách trạng thái tất cả outlet |
| **ISTAT** | Công suất đầu vào, dòng điện |
| **ENVMON** | Cảm biến môi trường (nhiệt độ, độ ẩm) |
| **VERSION** | Firmware và phiên bản phần cứng |

### Tab 4 — Command Builder

Xây dựng lệnh phân cấp: `<Command> <Parameter>`.

| Combobox | Ví dụ Parameter | Lệnh gửi |
|---|---|---|
| `LIST` | `PORTS` | `LIST PORTS\r\n` |
| `SHOW` | `CONFIG` | `SHOW CONFIG\r\n` |
| `SET` | `PORT 1 NAME WebSrv` | `SET PORT 1 NAME WebSrv\r\n` |
| `CREATE` | `USER bob` | `CREATE USER bob\r\n` |
| `DELETE` | `USER bob` | `DELETE USER bob\r\n` *(xác nhận)* |
| `PING` | `192.168.1.1` | `PING 192.168.1.1\r\n` |
| `RESTART` | *(trống)* | `RESTART\r\n` *(xác nhận)* |

### Tab 5 — Raw Terminal

Gõ bất kỳ lệnh nào và gửi thẳng xuống socket — mô phỏng CLI thật.  
Phím `Enter` tương đương nút **SEND RAW**.

> ⚠️ Tab này bỏ qua mọi input validation. Chỉ dùng khi cần debug.

### Global Terminal Output

- Nền đen (`#080808`), chữ xanh `lime`
- Hiển thị toàn bộ raw output từ thiết bị
- Color-coded: lỗi = đỏ, info = xanh dương, lệnh = xanh lá nhạt

---

## Tham chiếu lệnh MRV LX-5250

### Lệnh quản lý outlet

```
ON  <port>           Bật nguồn outlet
OFF <port>           Tắt nguồn outlet
REBOOT <port>        Power-cycle outlet (OFF → delay → ON)
CONNECT <port>       Mở phiên reverse Telnet đến thiết bị tại port
STATUS               Hiển thị trạng thái tất cả outlet
ISTAT                Thông tin dòng điện đầu vào
```

### Lệnh hệ thống

```
ENVMON               Đọc cảm biến môi trường
VERSION              Thông tin firmware/hardware
LIST [PORTS|USERS]   Liệt kê ports hoặc users
SHOW [CONFIG|...]    Hiển thị cấu hình
SET  <target> <val>  Thiết lập tham số
```

### Lệnh quản trị nâng cao

```
CREATE USER <name>   Tạo tài khoản người dùng
DELETE USER <name>   Xoá tài khoản người dùng
PING <ip>            Ping từ thiết bị tới IP chỉ định
RESTART              Khởi động lại hệ thống PDU
```

---

## Bảo mật (Blue Team Notes)

> **CẢNH BÁO:** Telnet là giao thức plaintext. Toàn bộ lưu lượng — bao gồm
> credentials — có thể bị sniff trên mạng. **Chỉ dùng trong môi trường lab**
> hoặc mạng quản lý riêng biệt (OOB management network).  
> Môi trường production nên dùng SSH.

### Các biện pháp bảo vệ đã implement

| Biện pháp | Chi tiết |
|---|---|
| **Security banner** | Label đỏ vĩnh viễn trên toàn bộ UI |
| **Keystroke filter** | Port ID chặn tại widget level (validatecommand) |
| **Pre-send validation** | Kiểm tra lại trước khi bytes chạm socket |
| **Confirmation dialog** | `OFF`, `DELETE`, `REBOOT` yêu cầu `askyesno` |
| **Credential redaction** | Password không bao giờ xuất hiện trong log |
| **Outbound IAC escaping** | `0xFF` được escape thành `0xFF 0xFF` khi gửi |
| **TCP_NODELAY** | Tắt Nagle buffering — lệnh gửi tức thì |
| **Specific exceptions** | Không có bare `except:` — bắt từng loại lỗi |

### Khuyến nghị triển khai production

```
KHÔNG NÊN                          NÊN
─────────────────────────────────────────────────────
Dùng Telnet qua LAN thường         Dùng SSH (port 22)
Để thiết bị trực tiếp trên LAN     Đặt sau OOB management VLAN
Dùng tài khoản Admn mặc định       Tạo tài khoản cá nhân, đặt MFA
Để log file mrv_gui.log không mã   Mã hoá log hoặc forward to SIEM
```

---

## Xử lý sự cố

### Lỗi "Cannot connect"

```
[CONN ERROR] Cannot connect to 192.168.1.252:23: [WinError 10060]
```

- Kiểm tra IP và port đúng chưa
- Ping thiết bị: `ping 192.168.1.252`
- Đảm bảo không có firewall chặn port 23
- Kiểm tra Telnet có được bật trên thiết bị không

### Lỗi "Auth timeout"

```
[AUTH ERROR] Timeout (12s) waiting for one of ['Password: ', 'password: ', 'Passwd: ']
Last received: 'Username: Admn\r\n...'
```

- Username sai: thiết bị gửi lại "Username: " thay vì "Password: "
- Thiết bị dùng prompt khác — xem log để thấy `Last received` và báo cáo
- Thêm variant password prompt vào `_PROMPT_PASS` trong `mrv_backend.py`

### UI bị đóng băng

Không thể xảy ra theo thiết kế — mọi I/O mạng chạy trên worker thread daemon.
Nếu gặp trường hợp này, kiểm tra xem có code nào gọi `backend.*` từ main thread không.

### Log file

```
mrv_gui.log     # ghi cả DEBUG level — xem chi tiết IAC negotiation
```

---

## Ghi chú kỹ thuật — Vấn đề IAC

### Tại sao không dùng `telnetlib`?

`telnetlib` bị **deprecated từ Python 3.11** và **xoá hoàn toàn từ Python 3.13**.
Dự án này implement RFC 854 thủ công qua `_TelnetIAC` với cùng API semantics.

### Root cause của timeout 5 phút (đã sửa)

```
TRƯỚC KHI SỬA (raw socket):
  Sau khi gửi username, device gửi thêm IAC negotiations MỚI
  xen kẽ vào stream cùng "Password: "

  Stream thô:     FF FC 01  FF FC 03  FF FE 01  70 61 73 73 77 6F 72 64 20 3A 20
  Vấn đề:         ←IAC WONT→←IAC WONT→←IAC DONT→ ←── "password: " ────────────►
  Kết quả:        _read_until() không thấy "Password: " → timeout 8s

SAU KHI SỬA (_TelnetIAC):
  _parse_iac() gọi sau MỖI recv() strip toàn bộ IAC bytes trước
  read_until_any() nhận clean stream → "Password: " được thấy ngay
```

### Luồng IAC handshake quan sát thực tế

```log
Telnet: WILL 0x01  ->  DONT    # server muốn echo — ta từ chối
Telnet: WILL 0x03  ->  DONT    # server muốn suppress-go-ahead — từ chối
Telnet: DO   0x01  ->  WONT    # server bảo ta echo — ta từ chối
Telnet: DO   0x03  ->  WONT    # server bảo ta suppress-go-ahead — từ chối
Telnet: WONT 0x01  (no reply)  # server acknowledge, không cần reply
Telnet: WONT 0x03  (no reply)
Telnet: DONT 0x01  (no reply)
Telnet: WONT 0x0d  (no reply)
Username sent.
Password sent.  [REDACTED FROM LOG]
Awaiting 'LX: ' command prompt ...
Authenticated — LX: prompt received.   ✅
```

---

## Changelog

| Phiên bản | Mô tả |
|---|---|
| v1.0 | Single-file `mrv_lx5250_gui.py` — raw socket, bị timeout IAC |
| v1.1 | Sửa `mrv_lx5250_gui.py` — thêm `_TelnetIACHandler`, vẫn bị timeout password |
| **v2.0** | **2-file: `mrv_backend.py` + `gui_main.py`** — `read_until_any()`, auth hoạt động hoàn toàn |

---

*Developed by: Senior Software Engineer / Blue Team Security*  
*Target device: MRV LX-5250 Firmware v5.3f*  
*Python: 3.10+ (tested on 3.13, 3.14)*
