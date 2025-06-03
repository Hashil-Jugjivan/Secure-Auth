import sqlite3
import string
import time
import hashlib
import getpass
import password_generator
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
DB_PATH = r"vault.db"

def init_db():
    # connect to vault.db
    conn = sqlite3.connect(DB_PATH)

    # use a cursor to execute SQL commands
    cursor = conn.cursor()

    #create users table if it doesnt exist
    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS users(
                        username TEXT PRIMARY KEY,
                        salt BLOB NOT NULL,
                        pw_hash BLOB NOT NULL,
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

def store_new_user(cursor: sqlite3.Cursor, username: str, user_salt: bytes, pw_hash: bytes):
    """Store a new user and their details in the database"""
    created_at = int(time.time())
    cursor.execute("INSERT INTO users (username, salt, pw_hash, created_at) VALUES (?, ?, ?, ?);",
                   (username, user_salt, pw_hash, created_at)
    )

def fetch_user_records(cursor: sqlite3.Cursor, username: str): 
    """Fetch user records from the database by username"""
    cursor.execute("SELECT salt, pw_hash FROM users WHERE username = ?;", (username,)
    )
    return cursor.fetchone() 

def derive_user_hash(password: str, user_salt: bytes) -> bytes:
    """Derive a 32-byte PBKDF2-HMAC-SHA256 key from the password and salt"""
    """Uses 200,000 iterations to slow down brute-force attacks"""
    """Returns raw 32-byte hash, not hex"""
    return hashlib.pbkdf2_hmac('sha256', password.encode("utf-8"), user_salt, 200000, dklen=32)

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

    # (1) Ensure unique username
    while True:
        username = input("Please enter your username: ").strip()
        if user_exists(cursor, username):
            print("Username already exists. Please choose a different one.")
        else:
            break
    # (2) Generate or manual password entry
    choice = input("Generate a strong password for me? (Y/N): ").strip().lower()
    # (2a) Auto generate strong password for user
    if choice == 'y' or choice == 'yes':
        while True:
            generated_pwd = password_generator.generate_password(length=12, use_uppercase=True, use_numbers=True, use_special_chars=True)
            print(f"Your generated password is: \n\n {generated_pwd}\n")
            print("This will remain visible for 5 seconds, please copy or note it down.")
            time.sleep(5)
            print("\n" * 30) # Clear the screen
            password = generated_pwd
            break
    else: 
        # (2b) Manual password entry by user
        while True:
            password = getpass.getpass("Please enter your password: ")
            retype_password = getpass.getpass("Please re-enter your password: ")
            if password != retype_password:
                print("Passwords do not match. Please try again.")
                continue

            if not password_strength(password):
                print("Password does not meet the strength requirements. Please try again.")
                continue

            break
    
    # (3) Generate the salt and hash
    user_salt = os.urandom(16)  # Generate a random 16-byte salt
    pw_hash = derive_user_hash(password, user_salt)
    password = None # Clear the password from memory

    # (4) Insert user entry into DB and commit changes
    store_new_user(cursor, username, user_salt, pw_hash)
    conn.commit()
    print("Account created successfully.\n")

def login(conn: sqlite3.Connection) -> bool:
    cursor = conn.cursor()
    username = input("Please enter your username: ")

    # Fetch the salt and pw from DB
    record = fetch_user_records(cursor, username)
    if record is None:
        print("No user found with that username.")
        return False
    
    user_salt, stored_hash = record
    
    # Get the password from the user, derive and compare the hash
    pw_try = getpass.getpass("Please enter your password: ")
    derived_try = derive_user_hash(pw_try, user_salt)
    pw_try = None  # Clear the password from memory

    if derived_try == stored_hash:
        print("✅ Login Successful!\n")
        return True
    else:
        print("❌ Invalid Password!\n")
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














