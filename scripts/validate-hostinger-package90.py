"""Compatibility entry point for the direct-folder deployment validator."""
import runpy
from pathlib import Path
runpy.run_path(str(Path(__file__).with_name('validate-hostinger-folder91.py')),run_name='__main__')
