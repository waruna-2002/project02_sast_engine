import os
import sqlite3

# SEC-001: Hardcoded AWS API Key / Secret (CRITICAL)
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE12345"
API_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

def user_login(username, password):
    # SEC-SQLI: Potential SQL Injection Hazard (HIGH)
    db = sqlite3.connect("users.db")
    cursor = db.cursor()
    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
    cursor.execute(query)
    return cursor.fetchone()

def execute_command(user_input):
    # SEC-004: Dangerous Eval / Command Injection Sinks (CRITICAL)
    eval(user_input)
    os.system("ping -c 1 " + user_input)

if __name__ == "__main__":
    print("Running vulnerable code sample...")
    user_login("admin' --", "password")
    execute_command("print('Testing Code Execution')")