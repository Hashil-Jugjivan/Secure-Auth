# 🔐 SecureAuth: A Cybersecurity-Focused Python Login System

A command-line password manager built in Python, designed with **cybersecurity best practices** to protect user credentials and simulate real-world secure login systems.

---

## 📦 Features

### ✅ Core Functionality

- Account creation with username, email, and strong password
- Secure login with password and email-based One-Time Password (OTP)
- Encrypted password hashing using **Argon2id**
- Password change/reset via verified email OTP
- Admin access to audit logs with hashed admin authentication

### 🔐 Security-Focused Implementations

| Feature                                 | Cybersecurity Principle          | Rationale                                                      |
| --------------------------------------- | -------------------------------- | -------------------------------------------------------------- |
| **Argon2id Password Hashing**           | Password Hardening               | Prevents brute-force attacks with strong KDF                   |
| **Pepper via .env**                     | Defense in Depth                 | Adds secret entropy outside the database                       |
| **Email-based OTP 2FA**                 | Multi-Factor Authentication      | Confirms user identity beyond password                         |
| **OTP Expiry & Verification**           | Time-bound Access Control        | Prevents reuse and replay of OTPs                              |
| **Rate Limiting & Account Lockout**     | Brute-force Protection           | Blocks repeated login/OTP attempts                             |
| **Audit Logging**                       | Monitoring & Accountability      | Tracks sensitive events (login, password reset, admin actions) |
| **Admin Access Control**                | Role-Based Access Control (RBAC) | Restricts log access behind secure hashed password             |
| **Password Strength Enforcement**       | Secure Defaults                  | Enforces strong user passwords on account creation/reset       |
| **Environment-based Secret Management** | Secure Configuration             | Keeps secrets out of source control                            |

---

## 🛡 Cybersecurity Concepts Demonstrated

### 1. **Password Security**

- Passwords are hashed using **Argon2id**, the most secure modern KDF
- Each password is salted and hashed; a global **pepper** from `.env` further protects against database compromise

### 2. **Multi-Factor Authentication (2FA)**

- Users must verify an OTP sent to their registered email during login and account creation
- OTPs are valid for only a few minutes and stored securely with expiration

### 3. **Rate Limiting & Lockouts**

- Failed login and OTP attempts are tracked
- Accounts are locked temporarily after repeated failed attempts to prevent brute-force attacks

### 4. **Secure Password Reset Workflow**

- Resets allowed only after email-based OTP verification
- New passwords must meet strength requirements
- OTPs are regenerated securely and expire quickly

### 5. **Audit Logging**

- Every sensitive action (e.g. login failure, OTP verification, password change, admin access) is logged with a timestamp
- Supports traceability and forensic analysis

### 6. **Admin Access Security**

- Admin password is stored as an Argon2id hash
- Admin login is audited, including failed attempts
- Access to audit logs is restricted to verified admin users only

---

## 🚀 How to Run

### 🧱 Prerequisites

- Python 3.9+
- Install dependencies:

```bash
pip install -r requirements.txt
```

### 🔐 Set Up `.env` Secrets

Create a `.env` file in the root directory:

```dotenv
PASSWORD_MANAGER_PEPPER=your_random_pepper_here
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_specific_password
ADMIN_PASSWORD_HASH=$argon2id$v=19$m=65536...  # generated using create_admin_hash.py
```

Do **NOT** commit `.env` to GitHub.

### 🏃 Run the App

```bash
python secure_auth.py
```

### 🧪 Use Cases

```
1. Create Account
2. Login
3. View Audit Log (Admin Only)
4. Change/Reset Password
5. Exit
```

---

## 📁 File Structure

```
.
├── secure_auth.py      # Main CLI logic
├── password_generator.py    # (Optional) Strong password generator
├── vault.db                 # SQLite DB with secure schema
├── .env                     # Secrets and configuration (ignored by Git)
├── .env.example             # Example config
└── README.md                # This documentation
```

---

## 📚 Future Improvements

- 🔒 Vault encryption for stored passwords using AES-GCM
- 🔁 Password reuse detection
- 🔗 Integration with HaveIBeenPwned for breach checks
- 🔐 Admin IP/device-based restrictions
- 📊 Web UI with Flask and JWT-based session auth

---

## 🛑 Disclaimer

This tool is for **educational purposes only**. Do not use in production environments without further review and hardening.

---

## ⭐ Give it a Star

If you're a fellow cyber-enthusiast or developer, feel free to ⭐ star this repo and explore the code!

