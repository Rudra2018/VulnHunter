"""
VulnHunter Demo: SQL Injection Vulnerability
This file contains intentionally vulnerable code for demonstration
"""

import sqlite3

class UserManager:
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()

    def authenticate_user(self, username, password):
        """
        VULNERABLE: SQL Injection via string concatenation
        An attacker could input: username = "admin' --" to bypass authentication
        """
        query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
        self.cursor.execute(query)
        return self.cursor.fetchone()

    def get_user_posts(self, user_id):
        """
        VULNERABLE: SQL Injection via f-string
        """
        query = f"SELECT * FROM posts WHERE user_id = {user_id}"
        self.cursor.execute(query)
        return self.cursor.fetchall()

    def search_users(self, search_term):
        """
        VULNERABLE: SQL Injection via format()
        """
        query = "SELECT * FROM users WHERE name LIKE '%{}%'".format(search_term)
        self.cursor.execute(query)
        return self.cursor.fetchall()

    def delete_user(self, user_id):
        """
        VULNERABLE: Dynamic SQL construction
        """
        table_name = "users"
        query = "DELETE FROM " + table_name + " WHERE id = " + str(user_id)
        self.cursor.execute(query)
        self.conn.commit()

# Example usage that would be exploitable
if __name__ == "__main__":
    manager = UserManager("users.db")

    # Normal usage
    user = manager.authenticate_user("john", "password123")

    # Malicious input that would cause SQL injection
    # attacker_input = "admin' OR '1'='1' --"
    # user = manager.authenticate_user(attacker_input, "anything")