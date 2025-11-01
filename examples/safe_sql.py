"""
VulnHunter Demo: Safe SQL Implementation
This file shows secure coding practices for database operations
"""

import sqlite3
from typing import Optional, List, Tuple

class SecureUserManager:
    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()

    def authenticate_user(self, username: str, password: str) -> Optional[Tuple]:
        """
        SECURE: Using parameterized queries prevents SQL injection
        """
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        self.cursor.execute(query, (username, password))
        return self.cursor.fetchone()

    def get_user_posts(self, user_id: int) -> List[Tuple]:
        """
        SECURE: Parameterized query with type validation
        """
        if not isinstance(user_id, int) or user_id <= 0:
            raise ValueError("Invalid user_id")

        query = "SELECT * FROM posts WHERE user_id = ?"
        self.cursor.execute(query, (user_id,))
        return self.cursor.fetchall()

    def search_users(self, search_term: str) -> List[Tuple]:
        """
        SECURE: Parameterized query with input validation
        """
        # Input validation
        if not search_term or len(search_term.strip()) == 0:
            return []

        # Sanitize search term
        search_term = search_term.strip()[:100]  # Limit length

        query = "SELECT * FROM users WHERE name LIKE ?"
        search_pattern = f"%{search_term}%"
        self.cursor.execute(query, (search_pattern,))
        return self.cursor.fetchall()

    def delete_user(self, user_id: int) -> bool:
        """
        SECURE: Parameterized query with proper validation
        """
        if not isinstance(user_id, int) or user_id <= 0:
            raise ValueError("Invalid user_id")

        try:
            # Use parameterized query
            query = "DELETE FROM users WHERE id = ?"
            self.cursor.execute(query, (user_id,))
            self.conn.commit()
            return self.cursor.rowcount > 0
        except sqlite3.Error as e:
            self.conn.rollback()
            raise e

    def create_user(self, username: str, email: str, password_hash: str) -> int:
        """
        SECURE: Safe user creation with validation
        """
        # Input validation
        if not all([username, email, password_hash]):
            raise ValueError("All fields are required")

        if len(username) > 50 or len(email) > 100:
            raise ValueError("Input too long")

        query = "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)"
        self.cursor.execute(query, (username, email, password_hash))
        self.conn.commit()
        return self.cursor.lastrowid

    def close(self):
        """Properly close database connection"""
        if self.conn:
            self.conn.close()

# Example of secure usage
if __name__ == "__main__":
    manager = SecureUserManager("users.db")

    try:
        # Safe operations
        user = manager.authenticate_user("john", "hashed_password")
        posts = manager.get_user_posts(123)
        search_results = manager.search_users("admin")

        # Even malicious input is handled safely
        malicious_input = "admin' OR '1'='1' --"
        # This will be treated as a literal string, not SQL code
        safe_search = manager.search_users(malicious_input)

    finally:
        manager.close()