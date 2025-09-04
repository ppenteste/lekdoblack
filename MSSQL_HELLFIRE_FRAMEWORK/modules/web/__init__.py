# modules/web/__init__.py
from .xss import XSSDetector
from .sqli import SQLInjector
from .lfi import LFITester
from .endpoints import EndpointDiscoverer

__all__ = [
    'XSSDetector',
    'SQLInjector',
    'LFITester',
    'EndpointDiscoverer'
]