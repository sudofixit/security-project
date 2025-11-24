# PHASE 4 - Database Security & Access Control 

# Database Simulation using a nested dictionary
student_db = {
    "admin": {
        "password": "adpass",
        "name": "Admin User",
        "email": "admin2313@cud.ac.ae",
        "role": "admin"
    },
    "student1": {
        "password": "s1pass",
        "name": "Student One",
        "email": "student0001@cud.ac.ae",
        "role": "student"
    },
    "student2": {
        "password": "s2pass",
        "name": "Student Two",
        "email": "student0002@cud.ac.ae",
        "role": "student"
    }
}

# Authentication Function
def auth(username, password):
    if username not in student_db:
        return None  # invalid username
    
    if student_db[username]["password"] != password:
        return None  # incorrect password
    
    return student_db[username]["role"]

# Role-Based Access Control Function
def access_control(role, username):
    if role == "admin":
        print("\nADMIN ACCESS GRANTED!")
        view_db = input("Do you want to view the entire student database? (yes/no): ")
        if view_db.lower() == "yes":
            for user, data in student_db.items():
                print(user, ":", data)
    else:
        print("\nSTUDENT ACCESS GRANTED!")
        print(username, ":", student_db[username])

# Simulating SQL Injection Detection Function
def simulateSQLInj(input_data):
    if "OR 1=1" in input_data.upper():
        print("\nWARNING: SQL Injection Attempt Detected!")
        safe_input = input_data.replace("OR 1=1", "")
        print("Blocked malicious part. Cleaned input:", safe_input)
        return safe_input
    return input_data

# Main Program
print("----- LOGIN SYSTEM WITH RBAC & SQLi PREVENTION -----")

username = input("Enter username: ")
password = input("Enter password: ")

# Simulate SQL injection on username before authentication
username_checked = simulateSQLInj(username)
password_checked = simulateSQLInj(password)

role = auth(username_checked, password_checked)

if not role:
    print("\nLogin Failed!")
else:
    print(f"\nLogin Successful! Role: {role}")
    access_control(role, username_checked)





