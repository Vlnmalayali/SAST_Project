import ast
import pytest
from app.core.detectors.sql_injection import SQLInjectionDetector
from app.core.detectors.command_injection import CommandInjectionDetector
from app.core.detectors.secrets import HardcodedSecretsDetector
from app.core.detectors.weak_crypto import WeakCryptoDetector
from app.core.detectors.deserialization import InsecureDeserializationDetector
from app.core.detectors.unsafe_eval import UnsafeEvalDetector
from app.core.detectors.xss import XSSDetector
from app.core.detectors.path_traversal import PathTraversalDetector


def _run_detector(detector, code: str):
    tree = ast.parse(code)
    lines = code.splitlines()
    return detector.detect(tree, "test.py", code, lines)


class TestSQLInjectionDetector:
    def test_detect_concat(self):
        code = '''
def get_user(uid):
    query = "SELECT * FROM users WHERE id = " + uid
    cursor.execute(query)
'''
        vulns = _run_detector(SQLInjectionDetector(), code)
        assert len(vulns) >= 1
        assert vulns[0].vulnerability_type == "sql_injection"

    def test_detect_fstring(self):
        code = '''
def get_user(uid):
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
'''
        vulns = _run_detector(SQLInjectionDetector(), code)
        assert len(vulns) >= 1

    def test_safe_parameterized(self):
        code = '''
def get_user(uid):
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
'''
        vulns = _run_detector(SQLInjectionDetector(), code)
        assert len(vulns) == 0


class TestCommandInjectionDetector:
    def test_detect_os_system(self):
        code = '''
def run(cmd):
    os.system("ls " + cmd)
'''
        vulns = _run_detector(CommandInjectionDetector(), code)
        assert len(vulns) >= 1
        assert vulns[0].vulnerability_type == "command_injection"

    def test_detect_subprocess_shell(self):
        code = '''
def run(cmd):
    subprocess.call(cmd, shell=True)
'''
        vulns = _run_detector(CommandInjectionDetector(), code)
        assert len(vulns) >= 1

    def test_safe_subprocess_list(self):
        code = '''
def run():
    subprocess.run(["ls", "-la"], shell=False)
'''
        vulns = _run_detector(CommandInjectionDetector(), code)
        assert len(vulns) == 0


class TestHardcodedSecretsDetector:
    def test_detect_hardcoded_password(self):
        code = 'password = "mysupersecretpassword"'
        vulns = _run_detector(HardcodedSecretsDetector(), code)
        assert len(vulns) >= 1

    def test_detect_aws_key(self):
        code = 'key = "AKIAIOSFODNN7EXAMPLE1234"'
        vulns = _run_detector(HardcodedSecretsDetector(), code)
        assert len(vulns) >= 1

    def test_ignore_placeholder(self):
        code = 'password = "changeme"'
        vulns = _run_detector(HardcodedSecretsDetector(), code)
        assert len(vulns) == 0


class TestWeakCryptoDetector:
    def test_detect_md5(self):
        code = 'h = hashlib.md5(data)'
        vulns = _run_detector(WeakCryptoDetector(), code)
        assert len(vulns) >= 1

    def test_safe_sha256(self):
        code = 'h = hashlib.sha256(data)'
        vulns = _run_detector(WeakCryptoDetector(), code)
        assert len(vulns) == 0


class TestInsecureDeserializationDetector:
    def test_detect_pickle(self):
        code = 'obj = pickle.loads(data)'
        vulns = _run_detector(InsecureDeserializationDetector(), code)
        assert len(vulns) >= 1

    def test_detect_yaml_unsafe(self):
        code = 'data = yaml.load(input_data)'
        vulns = _run_detector(InsecureDeserializationDetector(), code)
        assert len(vulns) >= 1

    def test_safe_yaml(self):
        code = 'data = yaml.load(input_data, Loader=yaml.SafeLoader)'
        vulns = _run_detector(InsecureDeserializationDetector(), code)
        assert len(vulns) == 0


class TestUnsafeEvalDetector:
    def test_detect_eval(self):
        code = 'result = eval(user_input)'
        vulns = _run_detector(UnsafeEvalDetector(), code)
        assert len(vulns) >= 1

    def test_safe_literal_eval(self):
        code = 'result = ast.literal_eval(data)'
        vulns = _run_detector(UnsafeEvalDetector(), code)
        assert len(vulns) == 0


class TestPathTraversalDetector:
    def test_detect_open_variable(self):
        code = '''
def read(fname):
    f = open(fname)
'''
        vulns = _run_detector(PathTraversalDetector(), code)
        assert len(vulns) >= 1

    def test_safe_open_constant(self):
        code = 'f = open("config.txt")'
        vulns = _run_detector(PathTraversalDetector(), code)
        assert len(vulns) == 0