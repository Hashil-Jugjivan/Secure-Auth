from dotenv import load_dotenv
from argon2 import PasswordHasher, exceptions as argon2_exceptions
import os
import sys
import sqlite3
import string
import time
import getpass
import password_generator
import random 
import smtplib
from email.message import EmailMessage

 # Load environment variables from .env file
load_dotenv() 

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
DB_PATH = r"vault.db"

ph = PasswordHasher(
    time_cost=4,  # Number of iterations
    memory_cost=2**16,  # Memory cost in KB
    parallelism=8,  # Number of threads
)

# Constants for login attempts and lockout
MAX_ATTEMPTS = 3  # Max failed login attempts before lockout
LOCKOUT_SECONDS = 600  # Lockout period in seconds (10 minutes)

def init_db():
    # connect to vault.db
    conn = sqlite3.connect(DB_PATH)

    # use a cursor to execute SQL commands
    cursor = conn.cursor()

    #create users table if it doesnt exist
    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS users(
                        username TEXT PRIMARY KEY,
                        pw_hash TEXT NOT NULL,
                        email TEXT UNIQUE, -- no duplicate emails allowed
                        created_at INTEGER NOT NULL 
                );
    """)
    # save changes to disk
    conn.commit() 

    # Check if the 'email' column already exists 
    # If not add it
    try:
        cursor.execute("PRAGMA table_info(users);")
        columns = [row[1] for row in cursor.fetchall()] # row[1] is the column name
        if "email" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN email TEXT UNIQUE;")
            conn.commit()
    except sqlite3.OperationalError:
        pass

    # Create the OTPs table if it doesnt exist
    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS otps(
                        username TEXT NOT NULL,
                        otp_code TEXT NOT NULL,
                        expires_at INTEGER NOT NULL,
                        PRIMARY KEY(username), -- only one OTP per user at a time
                        FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
                   );
    """)
    conn.commit()

    # Create login_attempts table to track failed login attempts
    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS login_attempts(
                    username TEXT NOT NULL,
                    attempt_time INTEGER NOT NULL,
                    success INTEGER CHECK(success IN (0, 1)), -- 0 for failed, 1 for successful
                    FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
                   );
    """)
    conn.commit()

    # Create audit log table to track security-sensitive actions
    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS audit_log(
                        id INTEGER PRIMARy KEY AUTOINCREMENT,
                        timestamp INTEGER NOT NULL,
                        username TEXT NOT NULL,
                        action TEXT NOT NULL,
                        details TEXT,
                        FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
                   );
    """)
    conn.commit()
                    
    return conn

def log_audit_event(cursor: sqlite3.Cursor, username: str, action: str, details: str = ""):
    """ Record a security-sensitive action in the audit log """
    timestamp = int(time.time())
    cursor.execute("INSERT INTO audit_log (timestamp, username, action, details) VALUES (?, ?, ?, ?);"
                   , (timestamp, username, action, details))
    cursor.connection.commit()  # Commit the changes to the database
    print(f"Audit log entry created for action: {action} by user: {username}")

def view_audit_log(conn: sqlite3.Connection):
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, username, action, details FROM audit_log ORDER BY timestamp DESC;")
    rows = cursor.fetchall()

    print("\n📋 Audit Log:")
    for ts, user, action, detail in rows:
        readable_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
        print(f"[{readable_time}] {user or 'N/A'} - {action}: {detail}")

def get_pepper() -> bytes:
    """Retrieve the pepper from environment variables."""
    pepper_hex = os.environ.get("PASSWORD_MANAGER_PEPPER")
    if not pepper_hex:
        print("ERROR: PASSWORD_MANAGER_PEPPER environment variable not set.")
        print("Please create a .env file with PASSWORD_MANAGER_PEPPER=<64-hex>.")
    try:
        return bytes.fromhex(pepper_hex)
    except ValueError:
        print("ERROR: PASSWORD_MANAGER_PEPPER must be a valid 64-character hex string.")
        exit(1)

def generate_otp(length: int = 6) -> str:
    """Generate a random numeric OTP of specified length."""
    otp = random.randint(0, 10**length - 1)
    return str(otp).zfill(length) # Pad with leading zeros if necessary

def store_otp(cursor: sqlite3.Cursor, username: str, otp_code: str, validity_seconds: int = 180):
    """ Insert or replace an row in the otps table for specific user
        The OTP will expire after validity_seconds seconds"""
    
    expires_at = int(time.time()) + validity_seconds

    # Insert or replace the OTP for the user
    cursor.execute(
        "INSERT OR REPLACE INTO otps(username, otp_code, expires_at) VALUES(?, ?, ?)",
        (username, otp_code, expires_at)
    )

def send_otp_via_email(recipient_email: str, otp_code: str):
    """ Send an email containing the OTP code to the receipient email"""

    # Load SMTP settings from environment variables
    host = os.environ.get("SMTP_HOST")
    port = int(os.environ.get("SMTP_PORT", 587))  # Default to 587 if not set
    user = os.environ.get("SMTP_USER")
    passwd = os.environ.get("SMTP_PASSWORD")

    if not all([host, port, user, passwd]):
        print("ERROR: SMTP configuration is not fully set in .env")
        sys.exit(1)

    # Build the email message
    msg = EmailMessage()
    msg['Subject'] = 'Your password manager OTP Code'
    msg['From'] = user
    msg['To'] = recipient_email
    msg.set_content(f"Your OTP code is: {otp_code}\n\nThis code is valid for 3 minutes.")

    # Connect to the SMTP server and send the email
    try:
        with smtplib.SMTP(host, port) as server:
            server.starttls() # Upgrade to secure connection (TLS)
            server.login(user, passwd) # Log in with SMTP credentials
            server.send_message(msg)
        print(f"✅ OTP sent to {recipient_email}")
    except Exception as e:
        print(f"❌ Failed to send OTP email: {e}")
        sys.exit(1)

def verify_otp(cursor: sqlite3.Cursor, username: str, otp_attempt: str) -> bool:
    """ Fetch the stored otp_code and expire_at from otp and verify the attempt """

    # Fetch the OTP code and expiration time for the user
    cursor.execute("SELECT otp_code, expires_at FROM otps WHERE username = ?;", (username,))
    row = cursor.fetchone()
    if not row:
        return False # No OTP found for this user
    
    # Unpack the row to get the variables
    stored_otp_code, expires_at = row
    now_timestamp = int(time.time())

    # Check if the OTP has expired
    if now_timestamp > expires_at:
        # otp has expired, clean it up
        cursor.execute("DELETE FROM otps WHERE username = ?;", (username,))
        return False 
    
    # Check if the OTP attempt matches the stored OTP code
    if otp_attempt == stored_otp_code:
        # OTP is correct, remove it so it cannot be reused
        cursor.execute("DELETE FROM otps WHERE username = ?;", (username,))
        return True
    
    return False # OTP attempt did not match the stored OTP code

def hash_password_with_argon2(plain_password: str) -> str:
    """ Hash a password string using a salt, pepper, and Argon2 """
    # Create per user salt
    user_salt = os.urandom(16)
    salt_hex = user_salt.hex()

    # Get pepper from environment variable
    pepper = get_pepper()

    # Combine salt, pepper, and password
    combined = user_salt + pepper + plain_password.encode('utf-8')

    # Hash the combined value using Argon2
    argon2_encoded = ph.hash(combined)

    # Return the salt and the Argon2 hash
    return f"{salt_hex}${argon2_encoded}"

def verify_password_with_argon2(stored_pw_hash: str, password_attempt: str) -> bool:
    """
    1. Split stored_pw_hash at the first "$" into:
       salt_hex (32 chars)  and  argon2_encoded (the rest).
    2. Convert salt_hex back to bytes.
    3. Reassemble: salt_bytes ∥ pepper_bytes ∥ attempt_password_bytes.
    4. ph.verify(argon2_encoded, combined_attempt).  
       If it matches, return True; otherwise return False.
    """

    try:
        salt_hex, argon2_encoded = stored_pw_hash.split('$', 1)
    except ValueError:
        # Malformed entry, no "$" found, treat as invalid
        return False    
    
    user_salt = bytes.fromhex(salt_hex) # Convert hex to bytes
    pepper =get_pepper() # Get pepper from environment variable
    attempt_input = user_salt + pepper + password_attempt.encode('utf-8')

    try:
        # Verify the password attempt against the stored hash
        return ph.verify(argon2_encoded, attempt_input)
    except argon2_exceptions.VerifyMismatchError:
        # If the password attempt does not match, return False
        return False
    except argon2_exceptions.VerificationError:
        # If there is an error in verification, return False
        return False
    
def record_login_attempt(cursor: sqlite3.Cursor, username: str, success: bool):
    """ Record a login attempt in the database """
    
    now = int(time.time())
    cursor.execute("INSERT INTO login_attempts (username, attempt_time, success) VALUES (?, ?, ?);",
                   (username, now, int(success))
    )

def check_account_lock_status(cursor: sqlite3.Cursor, username: str, max_attempts: int = 5, lockout_window_sec: int = 600) -> tuple[bool, int]:
    """
    Check if the account is locked due to too many failed login attempts.
    Returns a tuple (is_locked: bool, seconds_remaining: int).
    - is_locked: True if the account is locked, False otherwise.
    - seconds_remaining: If locked, the number of seconds until the lockout expires, otherwise 0.
    """

    now = int(time.time())
    window_start = now - lockout_window_sec

    # Count failed attempts in window
    cursor.execute("""
        SELECT attempt_time FROM login_attempts
        WHERE username = ? AND success = 0 AND attempt_time >= ?
        ORDER BY attempt_time ASC;
    """, (username, window_start))
    failed_attempts = cursor.fetchall()

    if len(failed_attempts) >= max_attempts:
        # First failed attempt that triggered lockout
        oldest_attempt = failed_attempts[0][0]
        unlock_time = oldest_attempt + lockout_window_sec
        seconds_remaining = max(0, unlock_time - now)
        return (True, seconds_remaining)

    return (False, 0)

def count_failed_attempts(cursor: sqlite3.Cursor, username: str, window_sec: int = LOCKOUT_SECONDS) -> int:
    """ Count the number of failed login attempts for a user within a specified time window """
    
    start_window = int(time.time()) - window_sec
    cursor.execute("""
        SELECT COUNT(*) FROM login_attempts
        WHERE username = ? AND success = 0 AND attempt_time >= ?;
        """, (username, start_window))
    
    return cursor.fetchone()[0]

def clear_failed_login_attempts(cursor: sqlite3.Cursor, username: str):
    """ Clear failed login attempts for a user after a successful login """
    cursor.execute("""
            DELETE FROM login_attempts
            WHERE username = ? AND success = 0;
            """, (username, ))
 
def user_exists(cursor: sqlite3.Cursor, username: str) -> bool:
    """Check if a user already exists in the database"""
    cursor.execute("SELECT 1 FROM users WHERE username = ?;", (username,))
    return cursor.fetchone() is not None

def store_new_user(cursor: sqlite3.Cursor, username: str, pw_hash_text: str, email: str):
    """Store a new user and their details in the database"""
    created_at = int(time.time())
    cursor.execute("INSERT INTO users (username, pw_hash, email, created_at) VALUES (?, ?, ?, ?);",
                   (username, pw_hash_text, email, created_at)
    )

def fetch_user_hash(cursor: sqlite3.Cursor, username: str): 
    """Fetch user records from the database by username"""
    cursor.execute("SELECT pw_hash FROM users WHERE username = ?;", (username,)
    )
    row = cursor.fetchone()
    return row[0] if row else None 

def password_strength(password: str) -> bool:
    """Check the strength of a password."""
    if len(password) < 10:
        print("Weak: Password must be at least 8 characters long.")
        return False
    
    if not any(char.isdigit() for char in password):
        print("Weak: Password must contain at least one digit.")
        return False
    
    if not any(char.isupper() for char in password):
        print("Weak: Password must contain at least one uppercase letter.")
        return False
    
    if not any(char.islower() for char in password):
        print("Weak: Password must contain at least one lowercase letter.")
        return False
    
    if not any(char in string.punctuation for char in password):
        print("Weak: Password must contain at least one special character.")
        return False

    return True

def create_account(conn: sqlite3.Connection):
    cursor = conn.cursor()

    # 1) Ensure username is unique
    while True:
        username = input("Enter a username: ").strip()
        if user_exists(cursor, username):
            print("Username already exists. Choose another.\n")
        else:
            break

    # 2) Choose auto-generate vs manual
    choice = input("Generate a strong password for me? (Y/N): ").strip().lower()
    if choice == 'y' or choice == 'yes':
        while True:
            generated_pw = password_generator.generate_password()
            print(f"\n Your generated password is:\n\n    {generated_pw}\n")
            print(" (Visible for 5 seconds—copy or note it now.)")
            time.sleep(5)
            print("\n" * 30)  # Clear screen

            # Assume user accepts it (or you could ask Y/N here)
            password = generated_pw
            break
    else:
        # 2b) Manual entry + confirm + complexity check
        while True:
            password = getpass.getpass("Enter a password: ")
            confirm = getpass.getpass("Retype the password: ")
            if password != confirm:
                print(" • Passwords do not match. Try again.\n")
                continue
            if not password_strength(password):
                print(" • Please choose a stronger password.\n")
                continue
            break

    # 3) Email address collection and OTP verification
    while True:
        email = input("Please enter your email address: ").strip()
    
        # Email format check
        if "@" not in email or "." not in email:
            print("Invalid email format. Please try again.\n")
            continue

        # Check if another user already registered with this email
        cursor.execute("SELECT 1 FROM users WHERE email = ?;", (email,))
        if cursor.fetchone():
            print("That email is already in use. Please use a different email.\n")
            continue

        # Generate a 6 digit OTP and store it in the database
        otp_code = generate_otp(6)
        store_otp(cursor, username, otp_code, validity_seconds=180)  # 3 minutes validity
        conn.commit()

        # Send the OTP via email
        print(f"An OTP has been sent to {email}. Please check your inbox.")
        send_otp_via_email(email, otp_code)

        # Primpt user to enter the OTP and verify it
        otp_attempt = input("Please enter the OTP sent to your email: ").strip()
        if verify_otp(cursor, username, otp_attempt):
            print("✅ Email verified successfully.\n")
            conn.commit()
            break
        else:
            print(" ❌ Invalid or expired OTP. Please try again.\n")
            # Loop back to re-enter email and generate a new OTP

    # 4) Argon2id + pepper hashing
    pw_hash_text = hash_password_with_argon2(password)

    # Overwrite plaintext password in memory (optional good practice)
    password = None

    # 5) Insert into DB and commit
    store_new_user(cursor, username, pw_hash_text, email)
    conn.commit()
    print("✅ Account created successfully.\n")

def login(conn: sqlite3.Connection) -> bool:
    cursor = conn.cursor()
    username = input("Please enter your username: ")

    # Check if the account is locked due to too many failed attempts (Rate limiting)
    is_locked, seconds_remaining = check_account_lock_status(cursor, username, MAX_ATTEMPTS, LOCKOUT_SECONDS)


    if is_locked:
        mins = seconds_remaining // 60
        secs = seconds_remaining % 60
        log_audit_event(cursor, username, "account_locked", f"Too many failed attempts in {LOCKOUT_SECONDS}s")
        print(f"🚫 Account locked due to too many failed attempts.")
        print(f"   Please try again in {mins} minutes {secs} seconds.")
        return False

    # Fetch the salt and pw from DB
    stored_pw_hash = fetch_user_hash(cursor, username)
    if stored_pw_hash is None:
        print("No user found with that username.")
        return False
    
    # Get the password from the user, derive and compare the hash
    pw_try = getpass.getpass("Please enter your password: ")

    if not verify_password_with_argon2(stored_pw_hash, pw_try):
        print("❌ Incorrect password. Please try again.")
        # Record the failed login attempt
        record_login_attempt(cursor, username, success=False)
        log_audit_event(cursor, username, "login_failed", "Invalid password")
        conn.commit()
        
        # Show remaining attempts
        recent_fails = count_failed_attempts(cursor, username, LOCKOUT_SECONDS)
        remaining_attempts = MAX_ATTEMPTS - recent_fails
        if remaining_attempts > 0:
            print(f"⚠️  You have {remaining_attempts} login attempt(s) remaining before account lockout.")
        else:
            print("🚫 Too many failed attempts. Your account is now temporarily locked.")

        return False
   
    # Record the successful login attempt
    record_login_attempt(cursor, username, success=True)
    conn.commit()
    
    # overwrite plaintext password in memory
    pw_try = None

    # Retrive the email address for OTP
    cursor.execute("SELECT email from users WHERE username = ?;", (username,))
    row = cursor.fetchone()
    if not row or not row[0]:
        print("ERROR: No email address associated with this account. Cannot send OTP.")
        return False
    user_email = row[0]

    # Generate & send otp to users email for 2FA
    otp_code = generate_otp(6)
    store_otp(cursor, username, otp_code, validity_seconds=180)  # 3 minutes validity
    conn.commit()

    print(f"An OTP has been sent to {user_email}. Please check your inbox.")
    send_otp_via_email(user_email, otp_code)

    # Prompt user to enter the OTP and verify it
    otp_attempt = input("Please enter the 6 digit OTP sent to your email: ").strip()
    if verify_otp(cursor, username, otp_attempt):
        log_audit_event(cursor, username, "login_success", "MFA verified") # Log successful login
        clear_failed_login_attempts(cursor, username)  # Clear previous failed attempts
        conn.commit()
        print("✅ Login successful. Welcome back!")
        return True
    else:
        log_audit_event(cursor, username, "otp_failed", "Incorrect OTP entered") # Log failed OTP attempt
        print(" ❌ Invalid or expired OTP. Please try again.")
        return False

def main():
    conn = init_db()
    if conn is None:
        print("Failed to connect to the database.")
        return
    
    while True:
        print("Welcome to the Password Manager")
        print("1. Create Account")
        print("2. Login")
        print("3. Exit")
        choice = input("Please choose an option (1-3): ")

        if choice == '1':
            create_account(conn)
        elif choice == '2':
            login(conn)
        elif choice == '3':
            conn.close()
            print("Exiting the Password Manager. Goodbye!")
            break
        else:
            print("Invalid Choice. Please try again.")
     
if __name__ == "__main__":
    main()

#dhvv sqff kgec uqlv 
