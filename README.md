# 🔐 Simple AES Text Encryptor

โปรแกรม Python สำหรับ **เข้ารหัส** และ **ถอดรหัสข้อความ** โดยใช้ **AES (Advanced Encryption Standard)** และ **Secret Key** ที่กำหนดโดยผู้ใช้  
ใช้งานผ่าน **Command Line Interface (CLI)** ได้ง่ายและปลอดภัย

## 🚀 คุณสมบัติ

- เข้ารหัสข้อความด้วย AES-256 CBC mode
- ใช้ Secret Key ที่กำหนดเอง
- ถอดรหัสข้อความที่ถูกเข้ารหัส
- ใช้งานง่ายผ่านเมนูใน Terminal

## 🧑‍💻 วิธีติดตั้ง

1. คลิก Clone หรือดาวน์โหลดโปรเจกต์นี้
2. ติดตั้งไลบรารีที่จำเป็นด้วยคำสั่ง:

```bash
pip install pycryptodome
```

## ▶️ วิธีใช้งาน

รันไฟล์ Python ด้วยคำสั่ง:

```bash
python your_script_name.py
```

จากนั้นจะมีเมนูให้เลือก:

```
=== เมนูการเข้ารหัส/ถอดรหัส ===

1. เข้ารหัสข้อความ
2. ถอดรหัสข้อความ

กรุณาเลือก (1 หรือ 2):
```

### 📌 ตัวอย่างการเข้ารหัส

```
📥 ข้อความที่ต้องการเข้ารหัส: Hello World
🔑 Secret Key: mypassword123

✅ ข้อความที่เข้ารหัสแล้ว:
T1Mzx1H4ItpNKn5iy1T1mA==:3zMyUV7Ee9tuVDMIKpekgQ==
```

### 🔓 ตัวอย่างการถอดรหัส

```
📥 ข้อความที่ต้องการถอดรหัส: T1Mzx1H4ItpNKn5iy1T1mA==:3zMyUV7Ee9tuVDMIKpekgQ==
🔑 Secret Key: mypassword123

✅ ข้อความที่ถอดรหัสแล้ว:
Hello World
```

## 🛡️ ความปลอดภัย

- ใช้ `SHA-256` สร้างคีย์ความยาว 256 บิตจาก Secret Key
- มีการใช้ `IV` (Initialization Vector) แบบสุ่มสำหรับแต่ละข้อความ เพื่อความปลอดภัยสูงขึ้น
- ผลลัพธ์เป็น base64 สามารถคัดลอกเก็บไว้ได้ง่าย

## 📂 โครงสร้างไฟล์

```
.
├── encryptor.py     # ไฟล์หลักสำหรับเรียกใช้งาน
└── README.md        # เอกสารนี้
```

## 📘 ไลบรารีที่ใช้

- [pycryptodome](https://pypi.org/project/pycryptodome/)