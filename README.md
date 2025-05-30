

---

# 🔐 Digital Signature System

This is a **Digital Signature System** built using **Streamlit** and **MySQL**, allowing users to securely sign and verify messages using **DSA (Digital Signature Algorithm)**.

### Features:
- **User Registration & Authentication** (via **bcrypt** password hashing)
- **DSA Key Pair Generation** (private & public keys with encryption)
- **Message Signing** (sign messages using private keys)
- **Signature Verification** (verify signatures using public keys)
- **Signature Expiry System** (automatic expiration after a set time)

---

## 🚀 Installation & Setup

### 1️⃣ Install Dependencies

Make sure you have **Python 3** installed. Then, install the required dependencies:

```bash
pip install streamlit mysql-connector-python bcrypt cryptography
```

### 2️⃣ Set Up MySQL Database

Start your MySQL server and create a new database:

```sql
CREATE DATABASE digital_signature_db;
```

### 3️⃣ Run the Application

To start the **Streamlit** web application, run:

```bash
streamlit run app.py
```

---

## 📌 Features & Usage

### 1️⃣ **User Registration & Authentication**
Before using the system, users must **register** with a **username** and **password**.

- **Register a User:**
  - Go to **Register** in the sidebar.
  - Enter your **Username** and **Password**.
  - Click **Register**.

- **Login:**
  - Go to **Login** in the sidebar.
  - Enter your **Username** and **Password**.
  - Click **Login**.

> Passwords are securely hashed using **bcrypt** before storing in the database.

---

### 2️⃣ **Generate DSA Key Pair**
Once registered, generate a **DSA key pair** to sign messages.

- **Steps:**
  - Go to **Generate Key**.
  - Enter **Username** and a **Key Name** (e.g., "mykey").
  - Enter a **password** for key encryption.
  - Click **Generate Key**.

> The private key is encrypted and saved securely.  
> The public key is stored separately for verification.

---

### 3️⃣ **Sign a Message**
To create a **digital signature**, follow these steps:

- Go to **Sign Message**.
- Enter **Username** and the **Message**.
- Enter **Key Name** and **Key Password**.
- Click **Sign**.

> The system generates a **signature file** and stores it.  
> The signature will expire after **30 days** (default).

---

### 4️⃣ **Verify a Signature**
To verify the authenticity of a signed message:

- Go to **Verify Signature**.
- Enter the **Signature File Path**.
- Enter the **Original Message**.
- Enter the **Public Key File Path**.
- Click **Verify**.

> If the signature matches and is not expired, it will be **verified successfully**.

---

## 🔑 Example Usage

### 📌 1. Generate Key Pair
```python
generate_key(username="john_doe", key_name="mykey", password="secure123")
```

**Generated Files:**
- `keys/john_doe_mykey_private.pem`
- `keys/john_doe_mykey_public.pem`

---

### 📌 2. Sign a Message
```python
sign_message(username="john_doe", message="Hello, world!", key_name="mykey", password="secure123")
```

**Generated Signature:**
- `signatures/john_doe_20250328123045.sig`

---

### 📌 3. Verify the Signature
```python
verify_signature(
    signature_path="signatures/john_doe_20250328123045.sig",
    message="Hello, world!",
    public_key_path="keys/john_doe_mykey_public.pem"
)
```

**Output:**
✅ Signature verified!

---

## 📂 Project Structure

```
/digital_signature_system
│── app.py              # Main Streamlit application
│── README.md           # Documentation
│── requirements.txt    # Python dependencies
│── keys/               # Stores private and public keys
│── signatures/         # Stores signature files
└── database/
    └── digital_signature_db.sql   # MySQL database schema
```

---

## 🛡️ Security Considerations
- **Passwords** are securely stored using **bcrypt** hashing.
- **Private keys** are **encrypted** before storage.
- **Signatures expire** automatically to prevent misuse.

**Video Link:**
https://drive.google.com/file/d/1uVj5CSoqOgNw15cInCjUz4STbLeaFyPM/view?usp=sharing


---


