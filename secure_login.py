import re

# Database Simulation
users = [
    {"username": "admin", "password": "12345"},
    {"username": "student", "password": "pass123"}
]

def validate_input(user_input):
    # Reject characters commonly used in injection attacks
    if re.search(r"[\'\";]|--", user_input):
        return False
    return True

print("----- Secure Login System -----")

username = input("Enter username: ")
password = input("Enter password: ")

# Input Validation
if not validate_input(username) or not validate_input(password):
    print("Invalid characters detected! Potential injection blocked.")
    exit()

# Secure comparison (no query building, no eval)
logged_in = False
for user in users:
    if user["username"] == username and user["password"] == password:
        logged_in = True
        break

if logged_in:
    print("Login Successful!")
else:
    print("Login Failed!")
