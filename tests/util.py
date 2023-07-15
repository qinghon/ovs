import subprocess
import sys
import os


def run_binary_file(binary_file_path, args=None, **kwargs):
    if args is None:
        args = []
    input_data = None
    if kwargs.get('input'):
        input_data = kwargs.get('input')

    result = subprocess.run([binary_file_path] + args, input=input_data, capture_output=True, **kwargs)
    code = result.returncode
    if code < 0:
        code = 128 + -code
    return result.stdout.decode(), result.stderr.decode(), code


def run_python_file(py_file_path, args=None, **kwargs):
    if args is None:
        args = []
    input_data = None
    if kwargs.get('input'):
        input_data = kwargs.get('input')
    if 'cwd' in kwargs:
        assert os.path.exists(kwargs['cwd']);
    result = subprocess.run([sys.executable, py_file_path] + args, input=input_data, capture_output=True, **kwargs)
    code = result.returncode
    if code < 0:
        code = 128 + -code
    return result.stdout.decode(), result.stderr.decode(), code


if __name__ == "__main__":
    print("")
