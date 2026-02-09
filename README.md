# QClone Studio Releases

Kho lưu trữ này chứa artefact phát hành công khai (appcast, gói update, chữ ký) cho ứng dụng **QClone Studio**.

## Cấu trúc thư mục

```text
qclone-releases/
├── appcast.xml
├── release_manager.py
├── update_public_key.pem
├── update_private_key.pem            # KHÔNG commit public
└── qclone_file_update/
    ├── manifest.json
    ├── qclone_update.ssu
    └── files/
```

## Cấu hình trong app chính

Trong `config/update_config.json` của app:

```json
{
  "enabled": true,
  "appcast_url": "https://raw.githubusercontent.com/Toanatp/qclone-releases/main/appcast.xml",
  "eddsa_public_key": "YOUR_PUBLIC_KEY_BASE64_HERE"
}
```

## Quy trình phát hành

1. Chuẩn bị file cập nhật trong `qclone_file_update/files/`.
2. Mở tool:

```powershell
python release_manager.py
```

3. Trong GUI:
- Bước 1: Tạo file `.ssu` (`qclone_update.ssu`)
- Bước 2: Tính SHA256
- Bước 3: Ký file bằng private key
- Bước 4: Cập nhật `appcast.xml`
- Bước 5: Commit & Push

4. Tạo GitHub Release với tag version và upload `qclone_update.ssu`.

## Lưu ý bảo mật

- Không commit `update_private_key.pem` lên public repo.
- Chỉ public key (`update_public_key.pem`) được nhúng vào app để verify update.
