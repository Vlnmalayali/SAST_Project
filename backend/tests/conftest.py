import pytest
from app.core.ast_parser import PythonASTParser


@pytest.fixture
def parser():
    return PythonASTParser()


@pytest.fixture
def vulnerable_python_code():
    return '''
import os
import hashlib
import pickle
import subprocess

# SQL Injection
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)

# Command Injection
def run_command(cmd):
    os.system("ls " + cmd)

# Hardcoded Secret
API_KEY = "AKIAIOSFODNN7EXAMPLE1234"
password = "supersecretpassword123"

# Weak Crypto
def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()

# Insecure Deserialization
def load_data(data):
    return pickle.loads(data)

# Unsafe Eval
def compute(expression):
    return eval(expression)

# XSS
def render_page(name):
    return f"<h1>Hello {name}</h1>"

# Path Traversal
def read_file(filename):
    with open(filename) as f:
        return f.read()
'''