import time
import hashlib
import getpass
import password_generator

password_manager = {}

def create_account():
    while True:
        username = input("Please enter your username: ")
        if username in password_manager:
            print("Username already exists. Please choose a different one.")
        else:
            break
    
    choice = input("Generate a strong password for me? (Y/N): ").strip().lower()
    if choice == 'y' or choice == 'yes':
        while True:
            generated_pwd = password_generator.generate_password(length=12, use_uppercase=True, use_numbers=True, use_special_chars=True)
            print(f"Your generated password is: \n\n {generated_pwd}\n")
            print("This will remain visible for 5 seconds, please copy or note it down.")
            time.sleep(5)
            password = generated_pwd
            break
    else: 
        while True:
            password = getpass.getpass("Please enter your password: ")
            retype_password = getpass.getpass("Please re-enter your password: ")
            if password != retype_password:
                print("Passwords do not match. Please try again.")
                continue

            if not password_generator.password_strength(password):
                print("Password does not meet the strength requirements. Please try again.")
                return

            break

    hashed_password = hashlib.sha256(password.encode()).hexdigest() 
    password_manager[username] = hashed_password
    print("Account created successfully.\n")

def login():
    username = input("Please enter your username: ")
    password = getpass.getpass("Please enter your password: ")
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    if username in password_manager.keys() and password_manager[username] == hashed_password:
        print("Login Successful!\n")
        return
    else:
        print("Invalid username or password.")

def main():
    while True:
        print("\n")
        print("Welcome to the Password Manager")
        print("1. Create Account")
        print("2. Login")
        print("3. Exit")
        choice = input("Please choose an option (1-3): ")
        if choice == '1':
            create_account()
        elif choice == '2':
            login()
        elif choice == '3':
            break
        else:
            print("Invalid Choice. Please try again.")
     
if __name__ == "__main__":
    main()














