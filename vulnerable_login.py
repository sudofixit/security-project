print("----- VULNERABLE LOGIN SYSTEM -----")

# Database Simulation
users = [
    {"username": "admin", "password": "12345"},
    {"username": "student", "password": "pass123"}
]

username = input("Enter username: ")
password = input("Enter password: ")

# Building vulnerable SQL-like query
query = f"username == '{username}' AND password == '{password}'"

print("\n[DEBUG] Raw Query:")
print(query)

# Convert SQL -> Python operators
py_query = query.replace("AND", "and").replace("OR", "or")

# Convert 1=1 -> 1==1 inside the user input
def fix_equals(text):
    parts = text.split("==")
    for i in range(len(parts)):
        if "=" in parts[i]:
            parts[i] = parts[i].replace("=", "==")
    return "==".join(parts)

py_query = fix_equals(py_query)

print("\n[DEBUG] Python Eval query:")
print(py_query)

# Vulnerable to SQL Injection
logged_in = False
for user in users:
    try:
        if eval(py_query, {}, user):
            logged_in = True
            break
    except:
        pass

if logged_in:
    print("\nLogin Successful!")
else:
    print("\nLogin Failed!")
