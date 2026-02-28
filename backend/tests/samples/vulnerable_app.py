"""
Sample vulnerable Python application for testing the SAST scanner.
Contains intentional vulnerabilities — DO NOT use in production.
"""

import os
import hashlib
import pickle
import subprocess
import sqlite3
import yaml


# --- SQL Injection ---
def get_user_by_id(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()


def search_users(name):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cursor.fetchall()


# --- Command Injection ---
def ping_host(hostname):
    os.system("ping -c 1 " + hostname)


def list_directory(path):
    result = subprocess.call(f"ls {path}", shell=True)
    return result


# --- Hardcoded Secrets ---
API_KEY = "sk-live-51234567890abcdefghijklmnopqrstuvwxyz"
DATABASE_PASSWORD = "SuperSecret123!@#"
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE1234"


# --- Weak Cryptography ---
def hash_user_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def hash_token(token):
    return hashlib.sha1(token.encode()).hexdigest()


# --- Insecure Deserialization ---
def load_user_session(session_data):
    return pickle.loads(session_data)


def load_config(config_string):
    return yaml.load(config_string)


# --- Unsafe Eval ---
def calculate(expression):
    return eval(expression)


def run_dynamic_code(code_string):
    exec(code_string)


# --- XSS ---
def render_greeting(name):
    return f"<h1>Welcome, {name}!</h1>"


def render_profile(user):
    html = "<div>" + user['bio'] + "</div>"
    return html


# --- Path Traversal ---
def read_user_file(filename):
    with open(filename) as f:
        return f.read()


def download_file(user_path):
    full_path = os.path.join("/var/data", user_path)
    with open(full_path) as f:
        return f.read()


# --- Safe Code (should NOT be flagged) ---
def safe_query(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def safe_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()


def safe_subprocess():
    subprocess.run(["ls", "-la"], shell=False, capture_output=True)


def safe_yaml(data):
    return yaml.safe_load(data)


def safe_eval(data):
    import ast
    return ast.literal_eval(data)