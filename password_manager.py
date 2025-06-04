from dotenv import load_dotenv
from argon2 import PasswordHasher, exceptions as argon2_exceptions
import sqlite3
import string
import time
import hashlib
import getpass
import password_generator
import os
import sys

 # Load environment variables from .env file
load_dotenv() 

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
DB_PATH = r"vault.db"

ph = PasswordHasher(
    time_cost=4,  # Number of iterations
    memory_cost=2**16,  # Memory cost in KB
    parallelism=8,  # Number of threads
)

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

def hash_password_with_argon2(plain_password: str) -> str:
    """Hash a password string using a salt, pepper, and Argon2"""
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
                        created_at INTEGER NOT NULL 
                );
    """)
    # save changes to disk
    conn.commit() 
    return conn

def user_exists(cursor: sqlite3.Cursor, username: str) -> bool:
    """Check if a user already exists in the database"""
    cursor.execute("SELECT 1 FROM users WHERE username = ?;", (username,))
    return cursor.fetchone() is not None

def store_new_user(cursor: sqlite3.Cursor, username: str, pw_hash_text: bytes):
    """Store a new user and their details in the database"""
    created_at = int(time.time())
    cursor.execute("INSERT INTO users (username, pw_hash, created_at) VALUES (?, ?, ?);",
                   (username, pw_hash_text, created_at)
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

    # 3) Argon2id + pepper hashing
    pw_hash_text = hash_password_with_argon2(password)

    # Overwrite plaintext password in memory (optional good practice)
    password = None

    # 4) Insert into DB and commit
    store_new_user(cursor, username, pw_hash_text)
    conn.commit()
    print("✅ Account created successfully.\n")


def login(conn: sqlite3.Connection) -> bool:
    cursor = conn.cursor()
    username = input("Please enter your username: ")

    # Fetch the salt and pw from DB
    stored_pw_hash = fetch_user_hash(cursor, username)
    if stored_pw_hash is None:
        print("No user found with that username.")
        return False
    
    # Get the password from the user, derive and compare the hash
    pw_try = getpass.getpass("Please enter your password: ")
    success = verify_password_with_argon2(stored_pw_hash, pw_try)
    pw_try = None  # Clear the password from memory

    if success:
        print("✅ Login successful.\n")
        return True
    else:
        print(" ❌ Invalid password.\n")
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