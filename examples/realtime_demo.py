#!/usr/bin/env python3
"""
VulnHunter Real-time Monitoring Demo
Creates test files to trigger real-time vulnerability analysis
"""

import os
import time
import shutil

def create_vulnerable_code():
    """Create files with various vulnerabilities to test real-time detection"""

    # Ensure examples directory exists
    os.makedirs('examples', exist_ok=True)

    # SQL Injection vulnerability
    sql_injection_code = '''
import sqlite3

def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # VULNERABLE: SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)

    result = cursor.fetchone()
    conn.close()
    return result

def main():
    user_input = input("Enter username: ")
    user = get_user(user_input)
    print(f"User found: {user}")

if __name__ == "__main__":
    main()
'''

    # XSS vulnerability
    xss_code = '''
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')

    # VULNERABLE: XSS
    template = f"<h1>Search Results for: {query}</h1>"
    return render_template_string(template)

@app.route('/comment', methods=['POST'])
def add_comment():
    comment = request.form.get('comment')

    # VULNERABLE: Stored XSS
    with open('comments.html', 'a') as f:
        f.write(f"<p>{comment}</p>")

    return "Comment added!"

if __name__ == "__main__":
    app.run(debug=True)
'''

    # Command injection vulnerability
    cmd_injection_code = '''
import os
import subprocess

def ping_host(hostname):
    # VULNERABLE: Command injection
    command = f"ping -c 4 {hostname}"
    result = os.system(command)
    return result

def check_file(filename):
    # VULNERABLE: Command injection
    cmd = f"ls -la {filename}"
    output = subprocess.check_output(cmd, shell=True)
    return output.decode()

def main():
    host = input("Enter hostname to ping: ")
    ping_host(host)

    file = input("Enter filename to check: ")
    print(check_file(file))

if __name__ == "__main__":
    main()
'''

    # Path traversal vulnerability
    path_traversal_code = '''
import os
from flask import Flask, request, send_file

app = Flask(__name__)

@app.route('/download')
def download_file():
    filename = request.args.get('file')

    # VULNERABLE: Path traversal
    file_path = os.path.join('uploads', filename)
    return send_file(file_path)

@app.route('/read')
def read_config():
    config_name = request.args.get('config', 'app.conf')

    # VULNERABLE: Path traversal
    config_path = f"config/{config_name}"

    try:
        with open(config_path, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    app.run()
'''

    # Write test files
    test_files = [
        ('examples/sql_injection_test.py', sql_injection_code),
        ('examples/xss_test.py', xss_code),
        ('examples/cmd_injection_test.py', cmd_injection_code),
        ('examples/path_traversal_test.py', path_traversal_code)
    ]

    print("🔍 Creating vulnerable test files for real-time monitoring...")

    for filename, content in test_files:
        print(f"  📝 Creating {filename}")
        with open(filename, 'w') as f:
            f.write(content)
        time.sleep(2)  # Allow time for monitoring to detect

    print("✅ Test files created! Check the real-time monitoring logs for vulnerability alerts.")

    # Also create a safe file to show the system doesn't false positive
    safe_code = '''
import hashlib
import logging

def hash_password(password: str) -> str:
    """Safely hash a password using SHA-256"""
    salt = "secure_salt_12345"
    return hashlib.sha256((password + salt).encode()).hexdigest()

def validate_input(user_input: str) -> bool:
    """Validate user input safely"""
    # Allow only alphanumeric characters
    return user_input.isalnum() and len(user_input) <= 50

def main():
    logger = logging.getLogger(__name__)
    logger.info("Starting secure application")

    password = input("Enter password: ")
    if validate_input(password):
        hashed = hash_password(password)
        logger.info(f"Password hashed successfully: {hashed[:10]}...")
    else:
        logger.warning("Invalid input provided")

if __name__ == "__main__":
    main()
'''

    print("  📝 Creating safe_code_example.py (should not trigger alerts)")
    with open('examples/safe_code_example.py', 'w') as f:
        f.write(safe_code)

    print("\n🎯 Real-time monitoring demo complete!")
    print("The VulnHunter real-time system should have detected vulnerabilities in:")
    print("  - sql_injection_test.py")
    print("  - xss_test.py")
    print("  - cmd_injection_test.py")
    print("  - path_traversal_test.py")
    print("\nCheck the monitoring system logs and WebSocket connections for alerts!")

if __name__ == "__main__":
    create_vulnerable_code()