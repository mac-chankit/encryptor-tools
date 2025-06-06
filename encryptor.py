from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import hashlib

# แปลง Secret Key เป็น 256-bit key
def get_key(secret_key):
    return hashlib.sha256(secret_key.encode()).digest()

# ฟังก์ชันเข้ารหัส
def encrypt(plain_text, secret_key):
    key = get_key(secret_key)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ":" + ct

# ฟังก์ชันถอดรหัส
def decrypt(encrypted_text, secret_key):
    try:
        key = get_key(secret_key)
        iv, ct = encrypted_text.split(":")
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ct)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except Exception as e:
        return f"❌ ถอดรหัสไม่สำเร็จ: {e}"

# เมนูหลัก
def main():
    print("=== เมนูการเข้ารหัส/ถอดรหัส ===")
    print("")
    print("1. เข้ารหัสข้อความ")
    print("2. ถอดรหัสข้อความ")
    print("")
    choice = input("กรุณาเลือก (1 หรือ 2): ")

    print("")

    if choice == '1':
        print("")
        message = input("📥 ข้อความที่ต้องการเข้ารหัส: ")
        secret = input("🔑 Secret Key: ")
        encrypted = encrypt(message, secret)
        print("")
        print("✅ ข้อความที่เข้ารหัสแล้ว:\n", encrypted)
    elif choice == '2':
        print("")
        encrypted_message = input("📥 ข้อความที่ต้องการถอดรหัส: ")
        secret = input("🔑 Secret Key: ")
        decrypted = decrypt(encrypted_message, secret)
        print("")
        print("✅ ข้อความที่ถอดรหัสแล้ว:\n", decrypted)
    else:
        print("❗ กรุณาเลือกแค่ 1 หรือ 2 เท่านั้น")

if __name__ == "__main__":
    main()
