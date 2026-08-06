import os

# Hardcoded API Secret (Rule: SEC-001)
api_key = "AIzaSyD-ExampleFakeKey12345"

# Dangerous Eval Sink (Rule: SEC-004)
user_input = input("Enter expression: ")
eval(user_input)

# Potential SQL Injection (% formatting)
query = "SELECT * FROM users WHERE username = '%s'" % user_input
