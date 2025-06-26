"""Create a password hash for the admin user."""

from argon2 import PasswordHasher
import getpass

ph = PasswordHasher()
admin_pw = getpass.getpass("Enter a new admin password: ")
pw_hash = ph.hash(admin_pw)

print("\nStore this in your .env as ADMIN_PASSWORD_HASH:\n")
print(pw_hash)
