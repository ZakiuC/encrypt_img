from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
from pathlib import Path
import os
import sys


def get_application_path():
    if getattr(sys, 'frozen', False):
        # 如果应用程序是“冻结”的，则使用这个路径
        application_path = os.path.dirname(sys.executable)
    else:
        # 否则，这是一个Python脚本，使用这个路径
        application_path = os.path.dirname(os.path.abspath(__file__))
    return application_path


def save_encrypted_data_to_file(encrypted_data, file_name):
    """将加密数据保存到文件，文件位于脚本同目录下的out文件夹内"""
    application_path = get_application_path()
    # 构建输出目录路径
    output_dir = os.path.join(application_path, 'out')
    # 如果输出目录不存在，创建它
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    # 构建完整的文件路径
    file_path = os.path.join(output_dir, file_name)
    
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)
    return file_path


def read_encrypted_data_from_file(file_path):
    """从文件读取加密数据"""
    with open(file_path, 'rb') as file:
        return file.read()
    
def encrypt_image(image_path, key):
    img = Image.open(image_path)
    img_byte_arr = img.tobytes()
    img_mode = img.mode
    img_size = img.size

    # 将图片的宽、高和模式编码成字符串并进行base64编码
    info_str = f"{img_mode},{img_size[0]},{img_size[1]}"
    info_str_encoded = base64.b64encode(info_str.encode('utf-8'))

    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_data = cipher.encrypt(pad(img_byte_arr, AES.block_size))

    # 将图片信息和加密数据一起编码为base64以便显示
    return base64.b64encode(iv + info_str_encoded + b',' + encrypted_data)

def decrypt_image(encrypted_data, key, output_path):
    encrypted_data_bytes = base64.b64decode(encrypted_data)
    iv = encrypted_data_bytes[:AES.block_size]
    encrypted_data = encrypted_data_bytes[AES.block_size:]

    # 分离图片信息和加密数据
    info_str_encoded, encrypted_data = encrypted_data.split(b',', 1)
    info_str = base64.b64decode(info_str_encoded).decode('utf-8')
    img_mode, img_width, img_height = info_str.split(',')

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    # 使用解析出的图片信息来恢复图片
    img = Image.frombytes(img_mode, (int(img_width), int(img_height)), decrypted_data)
    img.save(output_path)

def get_aes_key(password):
    from Crypto.Hash import SHA256
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()

def main():
    choice = input("Do you want to encrypt or decrypt an image? (e/d): ").strip().lower()
    if choice == 'e':
        image_path = input("Enter the path of the image to encrypt: ")
        password = input("Enter your encryption password: ")
        key = get_aes_key(password)
        encrypted_data = encrypt_image(image_path, key)
        # 假定加密数据的文件名
        encrypted_file_name = "encrypted_data.bin"
        encrypted_file_path = save_encrypted_data_to_file(encrypted_data, encrypted_file_name)
        print(f"Encrypted data saved to {encrypted_file_path}")
    elif choice == 'd':
        # 在main函数中更新解密部分
        encrypted_file_path = input("Enter the path of the encrypted data file: ")
        password = input("Enter your decryption password: ")
        key = get_aes_key(password)
        decrypted_file_name = input("Enter the file name for the decrypted image: ")
        if not decrypted_file_name.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif')):
            decrypted_file_name += '.png'  # 默认使用PNG格式
        application_path = get_application_path() # 使用 get_application_path 确保使用的是 exe 的路径
        output_dir = os.path.join(application_path, 'out')
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        output_path = os.path.join(output_dir, decrypted_file_name)
        encrypted_data = read_encrypted_data_from_file(encrypted_file_path)
        decrypt_image(encrypted_data, key, output_path)
        print(f"Image decrypted and saved to {output_path}")
    else:
        print("Invalid choice. Please enter 'e' to encrypt or 'd' to decrypt.")



if __name__ == "__main__":
    main()
    input("Press Enter to exit...")

