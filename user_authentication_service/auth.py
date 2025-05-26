#!/usr/bin/env python3
"""Authentication module for handling user registration, login, and sessions."""

import bcrypt
from uuid import uuid4
from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """Hashes a password using bcrypt.

    Args:
        password: The plain text password.

    Returns:
        The hashed password in bytes.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def _generate_uuid() -> str:
    """Generates a new UUID string.

    Returns:
        A string representation of a new UUID.
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        """Initialize a new Auth instance with a database connection."""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers a new user with email and hashed password.

        Args:
            email: The user's email address.
            password: The user's password.

        Returns:
            The newly created User object.

        Raises:
            ValueError: If the user already exists.
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except Exception:
            return self._db.add_user(email, _hash_password(password))

    def valid_login(self, email: str, password: str) -> bool:
        """Validates a user's login credentials.

        Args:
            email: The user's email.
            password: The password to check.

        Returns:
            True if credentials are valid, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(password.encode("utf-8"), user.hashed_password)
        except Exception:
            return False

    def create_session(self, email: str) -> str:
        """Creates a session ID for a user.

        Args:
            email: The user's email.

        Returns:
            A session ID as a string.
        """
        user = self._db.find_user_by(email=email)
        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> User or None:
        """Finds a user by session ID.

        Args:
            session_id: The session ID string.

        Returns:
            The User object or None.
        """
        if session_id is None:
            return None
        try:
            return self._db.find_user_by(session_id=session_id)
        except Exception:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroys a user's session.

        Args:
            user_id: The user's ID.

        Returns:
            None
        """
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Generates a password reset token for a user.

        Args:
            email: The user's email.

        Returns:
            A reset token as a string.

        Raises:
            ValueError: If user is not found.
        """
        try:
            user = self._db.find_user_by(email=email)
            reset_token = _generate_uuid()
            self._db.update_user(user.id, reset_token=reset_token)
            return reset_token
        except Exception:
            raise ValueError("User not found")

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates a user's password using a reset token.

        Args:
            reset_token: The password reset token.
            password: The new password.

        Raises:
            ValueError: If token is invalid.
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_password = _hash_password(password)
            self._db.update_user(
                user.id,
                hashed_password=hashed_password,
                reset_token=None
            )
        except Exception:
            raise ValueError("Invalid reset token")
