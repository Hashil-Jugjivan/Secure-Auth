import random 
import string

def generate_password(length=12, use_uppercase=True, use_numbers=True, use_special_chars=True):
    """Generate a random password with specified criteria."""
    if length < 10:
        raise ValueError("Password length must be at least 10 characters.")

    characters = string.ascii_lowercase  

    if use_uppercase:
        characters += string.ascii_uppercase
    if use_numbers:
        characters += string.digits
    if use_special_chars:
        characters += string.punctuation

    if not characters:
        raise ValueError("At least one character type must be selected.")

    password = ''.join(random.choice(characters) for i in range(length))
    return password

def generate_password2(length: int = 12):
    """Generate a random password of size length """
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(alphabet) for i in range(length))
    return password

def password_strength(password: str):
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

# pwd = generate_password(12, True, True, True)
# print(pwd)
# pwd2 = generate_password2(12)
# print(pwd2)

