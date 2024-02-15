"""
This module contains all the errors that can be raised by the application.
"""
user_not_found = Exception("user not found")
user_not_allowed = Exception("user not allowed")
user_failed_to_parse = Exception("user failed to parse")
header_malformed = Exception("header malformed")
header_missing = Exception("header missing")
