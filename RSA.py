import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
# cái này là tạo khóa
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("private_key.pem", "wb") as f:
        f.write(private_pem)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("public_key.pem", "wb") as f:
        f.write(public_pem)
    print("\n-----PRIVATE KEY-----")
    print(private_pem.decode())
    print("-----END PRIVATE KEY-----")
    print("-----PUBLIC KEY-----")
    print(public_pem.decode())
    print("-----END PUBLIC KEY-----")
    print(" Đã tạo và lưu khóa RSA.")
generate_keys()
    
  
# tạo chữ ký số 
def sign_image(image_path):
    
    with open(image_path, "rb") as img_file:
        image_data = img_file.read()
        image_hash = hashlib.sha256(image_data).digest()
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    signature = private_key.sign(
        image_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    sig_path = image_path + ".sig"
    with open(sig_path, "wb") as f:
        f.write(signature)
    
    print(f" Đã ký ảnh. Chữ ký lưu tại: {sig_path}")

# xác minh
def verify_signature(image_path, signature_path):
   
    with open(image_path, "rb") as img_file:
        image_data = img_file.read()
        image_hash = hashlib.sha256(image_data).digest()
    with open(signature_path, "rb") as f:
        signature = f.read()
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    try:
        public_key.verify(
            signature,
            image_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(" Chữ ký hợp lệ!")
    except Exception as e:
        print(" Chữ ký không hợp lệ.")

# mã hóa nè
def encrypt_data(data):
    
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    ciphertext = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext

# giải mã
def decrypt_data(ciphertext):
   
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext.decode()

# giao diện
def main():
    while True:
        print("\n--- CHỮ KÝ SỐ RSA CHO HÌNH ẢNH ---")
        print("1. Tạo cặp khóa RSA")
        print("2. Ký ảnh")
        print("3. Xác minh chữ ký")
        print("4. Mã hóa dữ liệu")
        print("5. Giải mã dữ liệu")
        print("0. Thoát")
        choice = input("Chọn: ")

        if choice == "1":
            generate_keys()
        elif choice == "2":
            path = input("Nhập đường dẫn ảnh cần ký: ")
            if os.path.exists(path):
                sign_image(path)
            else:
                print(" File ảnh không tồn tại.")
        elif choice == "3":
            img_path = input("Nhập đường dẫn ảnh: ")
            sig_path = input("Nhập đường dẫn chữ ký (.sig): ")
            if os.path.exists(img_path) and os.path.exists(sig_path):
                verify_signature(img_path, sig_path)
            else:
                print(" File ảnh hoặc chữ ký không tồn tại.")
        elif choice == "4":
            data = input("Nhập dữ liệu cần mã hóa: ")
            encrypted = encrypt_data(data)
            print(f" Dữ liệu đã được mã hóa: {encrypted.hex()}")
        elif choice == "5":
            encrypted_data = bytes.fromhex(input("Nhập dữ liệu mã hóa (hex): "))
            decrypted = decrypt_data(encrypted_data)
            print(f"Dữ liệu đã giải mã: {decrypted}")
        elif choice == "0":
            break
        else:
            print(" Lựa chọn không hợp lệ.")

if __name__ == "__main__":
    main()
