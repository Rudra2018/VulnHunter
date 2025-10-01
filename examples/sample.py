import os
import subprocess
import sqlite3

class UserManager:
    def __init__(self):
        self.connection = sqlite3.connect('users.db')
        self.cursor = self.connection.cursor()
    
    def vulnerable_get_user(self, user_id):
        # Vulnerable to SQL injection
        query = f"SELECT * FROM users WHERE id = {user_id}"
        self.cursor.execute(query)
        return self.cursor.fetchall()
    
    def safe_get_user(self, user_id):
        # Safe parameterized query
        query = "SELECT * FROM users WHERE id = ?"
        self.cursor.execute(query, (user_id,))
        return self.cursor.fetchall()

class CommandExecutor:
    def vulnerable_execute(self, command):
        # Vulnerable to command injection
        os.system(command)
    
    def safe_execute(self, command_parts):
        # Safe execution with subprocess
        result = subprocess.run(command_parts, capture_output=True, text=True)
        return result.stdout

def process_user_input_dangerous(user_input):
    # Dangerous - direct eval
    return eval(user_input)

def process_user_input_safe(user_input):
    # Safe - input validation
    if user_input.isdigit():
        return int(user_input)
    else:
        return user_input.strip()

def read_file_dangerous(filename):
    # Vulnerable to path traversal
    with open(filename, 'r') as f:
        return f.read()

def read_file_safe(filename):
    # Safe path handling
    base_dir = '/var/www/html'
    safe_path = os.path.join(base_dir, os.path.basename(filename))
    with open(safe_path, 'r') as f:
        return f.read()

def generate_html_dangerous(user_content):
    # Vulnerable to XSS
    return f"<div>{user_content}</div>"

def generate_html_safe(user_content):
    # Safe - escape user content
    import html
    return f"<div>{html.escape(user_content)}</div>"

# Buffer overflow vulnerable patterns (C-style)
def buffer_overflow_vulnerable():
    # This would be in C, but showing the pattern
    # char buffer[10];
    # strcpy(buffer, user_input);  // Vulnerable
    pass

def buffer_overflow_safe():
    # Safe buffer handling
    # char buffer[10];
    # strncpy(buffer, user_input, sizeof(buffer)-1);  // Safe
    # buffer[sizeof(buffer)-1] = '\0';
    pass

if __name__ == "__main__":
    print("Sample vulnerable and safe code patterns")
    
    # Test the safe methods
    executor = CommandExecutor()
    user_manager = UserManager()
    
    print("Safe command execution:")
    result = executor.safe_execute(['ls', '-l'])
    print(result)
    
    print("Safe user lookup:")
    users = user_manager.safe_get_user(1)
    print(users)
