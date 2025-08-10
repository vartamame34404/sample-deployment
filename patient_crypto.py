# patient_crypto.py

import mysql.connector
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import datetime
import numpy as np
import smtplib
from email.message import EmailMessage
import random
from PIL import Image
import re

# ------------------- DNA ENCRYPTION UTILS ------------------- #
def derive_key(dna_sequence: str) -> bytes:
    salt = b'static_salt_123'  # In production, use a secure random salt and store it safely
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(dna_sequence.encode())

def encrypt_data(data: str, key: bytes) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode()

def decrypt_data(encrypted_data: str, key: bytes) -> str:
    raw = base64.b64decode(encrypted_data)
    iv = raw[:16]
    encrypted = raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode()

# ------------------- DATABASE UTILS ------------------- #
def connect_db():
    # Railway format: mysql://root:password@host:port/database
    db_url = os.getenv("MYSQL_URL")
    if not db_url:
        raise ValueError("MYSQL_URL environment variable not set")

    match = re.match(r"mysql:\/\/(.*?):(.*?)@(.*?):(\d+)\/(.*)", db_url)
    if not match:
        raise ValueError("Invalid MySQL URL format. Check MYSQL_URL env variable.")

    user, password, host, port, database = match.groups()
    return mysql.connector.connect(
        host=host,
        user=user,
        password=password,
        database=database,
        port=int(port)
    )

def store_patient_data(patient_id, full_name, email, contact_number, dob, gender, address, dna_sequence):
    patient_id = int(patient_id)  # Ensure integer for DB
    key = derive_key(dna_sequence)
    now = datetime.datetime.now()

    conn = connect_db()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT 1 FROM sequence WHERE patient_id = %s", (patient_id,))
        if cursor.fetchone():
            raise ValueError("❌ Patient ID already exists. Please use a different one.")

        encrypted_data = {
            "patient_id": patient_id,
            "full_name": encrypt_data(full_name, key),
            "email": encrypt_data(email, key),
            "contact_number": encrypt_data(contact_number, key),
            "dob": encrypt_data(dob, key),
            "gender": encrypt_data(gender, key),
            "address": encrypt_data(address, key),
            "created_at": now.strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": now.strftime("%Y-%m-%d %H:%M:%S")
        }

        cursor.execute("""
            INSERT INTO patient_data (patient_id, full_name, email, contact_number, dob, gender, address, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, tuple(encrypted_data.values()))

        cursor.execute("""
            INSERT INTO sequence (patient_id, dna_sequence)
            VALUES (%s, %s)
        """, (patient_id, dna_sequence))

        conn.commit()
        return True

    except mysql.connector.Error as err:
        print("DB Error:", err)
        return False

    except ValueError as ve:
        raise ve

    finally:
        conn.close()

def retrieve_and_decrypt(patient_id):
    patient_id = int(patient_id)  # Ensure integer for DB
    conn = connect_db()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT dna_sequence FROM sequence WHERE patient_id = %s", (patient_id,))
        result = cursor.fetchone()
        if not result:
            return None

        dna_sequence = result[0]
        key = derive_key(dna_sequence)

        cursor.execute("SELECT * FROM patient_data WHERE patient_id = %s", (patient_id,))
        row = cursor.fetchone()
        if not row:
            return None

        decrypted_data = {
            "patient_id": patient_id,
            "full_name": decrypt_data(row[1], key),
            "email": decrypt_data(row[2], key),
            "contact_number": decrypt_data(row[3], key),
            "dob": decrypt_data(row[4], key),
            "gender": decrypt_data(row[5], key),
            "address": decrypt_data(row[6], key),
            "created_at": row[7],
            "updated_at": row[8]
        }

        return decrypted_data

    finally:
        conn.close()

def delete_patient_record(patient_id):
    patient_id = int(patient_id)  # Ensure integer for DB
    conn = connect_db()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT 1 FROM sequence WHERE patient_id = %s", (patient_id,))
        if not cursor.fetchone():
            return False, "❌ Patient ID not found."
        
        cursor.execute("SELECT 1 FROM patient_data WHERE patient_id = %s", (patient_id,))
        if not cursor.fetchone():
            return False, "❌ Patient ID not found."

        cursor.execute("DELETE FROM patient_data WHERE patient_id = %s", (patient_id,))
        cursor.execute("DELETE FROM sequence WHERE patient_id = %s", (patient_id,))
        conn.commit()
        return True, "✅ Patient record deleted successfully."

    except mysql.connector.Error as err:
        return False, f"❌ DB Error: {err}"

    finally:
        conn.close()
