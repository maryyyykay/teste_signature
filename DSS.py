import streamlit as st
import mysql.connector
import os
import bcrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key,
    Encoding, PrivateFormat, PublicFormat, BestAvailableEncryption
)
from datetime import datetime, timedelta

# Initialize Database
def init_db():
    conn = mysql.connector.connect(
        host='localhost', user='root', password='meethapanchan111', database='digital_signature_db'
    )
    cursor = conn.cursor()
    
    # Create necessary tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username VARCHAR(50) PRIMARY KEY,
            password VARCHAR(256) NOT NULL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS key_pairs (
            username VARCHAR(50),
            key_name VARCHAR(100),
            private_key_path VARCHAR(255),
            public_key_path VARCHAR(255),
            PRIMARY KEY (username, key_name)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS signatures (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50),
            message_hash VARCHAR(256),
            signature_path VARCHAR(255),
            expiry_date DATETIME
        )
    ''')
    
    conn.commit()
    return conn, cursor

conn, cursor = init_db()

# Hash password using bcrypt
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# Verify password using bcrypt
def check_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

# Register user
def register_user(username, password):
    try:
        cursor.execute('INSERT INTO users (username, password) VALUES (%s, %s)', (username, hash_password(password)))
        conn.commit()
        st.success("✅ Registration successful!")
    except mysql.connector.IntegrityError:
        st.error("🚫 Username already exists!")

# Login user
def login_user(username, password):
    cursor.execute('SELECT password FROM users WHERE username = %s', (username,))
    user = cursor.fetchone()
    return user and check_password(password, user[0])

# Generate DSA key pair
def generate_key(username, key_name, password):
    private_key = dsa.generate_private_key(key_size=2048)
    private_key_path = f'keys/{username}_{key_name}_private.pem'
    public_key_path = f'keys/{username}_{key_name}_public.pem'

    os.makedirs("keys", exist_ok=True)

    with open(private_key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=BestAvailableEncryption(password.encode())
        ))

    public_key = private_key.public_key()
    with open(public_key_path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ))

    cursor.execute('INSERT INTO key_pairs (username, key_name, private_key_path, public_key_path) VALUES (%s, %s, %s, %s)',
                   (username, key_name, private_key_path, public_key_path))
    conn.commit()
    st.success("🔑 Key pair generated successfully!")

# Sign message
# Sign message with proper error handling
def sign_message(username, message, key_name, password, expiry_days=30):
    cursor.execute('SELECT private_key_path FROM key_pairs WHERE username = %s AND key_name = %s', (username, key_name))
    key_result = cursor.fetchone()

    if not key_result:
        st.error("🚫 Key not found!")
        return None

    private_key_path = key_result[0]

    try:
        # Check if the key file exists
        if not os.path.exists(private_key_path):
            st.error("🚫 Private key file not found!")
            return None

        # Try loading the private key with password
        with open(private_key_path, 'rb') as key_file:
            try:
                private_key = load_pem_private_key(key_file.read(), password=password.encode())
            except ValueError:
                st.error("🚫 Incorrect password or corrupt private key file!")
                return None

        # Hash the message
        digest = hashes.Hash(hashes.SHA256())
        digest.update(message.encode())
        message_hash = digest.finalize()

        # Sign the hash
        signature = private_key.sign(message_hash, hashes.SHA256())

        os.makedirs("signatures", exist_ok=True)
        signature_path = f'signatures/{username}_{datetime.now().strftime("%Y%m%d%H%M%S")}.sig'
        with open(signature_path, 'wb') as f:
            f.write(signature)

        expiry_date = datetime.now() + timedelta(days=expiry_days)
        cursor.execute('INSERT INTO signatures (username, message_hash, signature_path, expiry_date) VALUES (%s, %s, %s, %s)',
                       (username, message_hash.hex(), signature_path, expiry_date))
        conn.commit()

        st.success("✅ Message signed successfully!")
        return signature_path

    except Exception as e:
        st.error(f"⚠️ Error signing message: {e}")
        return None


# Verify signature
def verify_signature(signature_path, message, public_key_path):
    cursor.execute('SELECT expiry_date FROM signatures WHERE signature_path = %s', (signature_path,))
    result = cursor.fetchone()

    if result and datetime.now() > result[0]:
        st.error("🚫 Signature has expired!")
        return False

    with open(public_key_path, 'rb') as key_file:
        public_key = load_pem_public_key(key_file.read())

    with open(signature_path, 'rb') as sig_file:
        signature = sig_file.read()

    # Recompute the hash of the original message
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode())
    message_hash = digest.finalize()

    try:
        public_key.verify(signature, message_hash, hashes.SHA256())
        st.success("✅ Signature verified!")
        return True
    except:
        st.error("🚫 Invalid signature!")
        return False

# Streamlit UI
st.title("🔐 Digital Signature System")

# User Authentication
menu = st.sidebar.radio("Navigation", ["Register", "Login", "Generate Key", "Sign Message", "Verify Signature"])

if menu == "Register":
    st.subheader("🆕 Register")
    new_username = st.text_input("Username")
    new_password = st.text_input("Password", type="password")
    if st.button("Register"):
        register_user(new_username, new_password)

elif menu == "Login":
    st.subheader("🔑 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if login_user(username, password):
            st.success(f"✅ Welcome, {username}!")
        else:
            st.error("🚫 Invalid username or password!")

elif menu == "Generate Key":
    st.subheader("🔑 Generate Key Pair")
    key_username = st.text_input("Username")
    key_name = st.text_input("Key Name")
    key_password = st.text_input("Encryption Password", type="password")
    if st.button("Generate Key"):
        generate_key(key_username, key_name, key_password)

elif menu == "Sign Message":
    st.subheader("📝 Sign Message")
    sign_username = st.text_input("Username")
    sign_message_text = st.text_area("Message to Sign")
    sign_key_name = st.text_input("Key Name")
    sign_password = st.text_input("Key Password", type="password")
    if st.button("Sign"):
        sign_message(sign_username, sign_message_text, sign_key_name, sign_password)

elif menu == "Verify Signature":
    st.subheader("✅ Verify Signature")
    verify_signature_path = st.text_input("Signature File Path")
    verify_message = st.text_area("Original Message")
    verify_public_key_path = st.text_input("Public Key File Path")
    if st.button("Verify"):
        verify_signature(verify_signature_path, verify_message, verify_public_key_path)

