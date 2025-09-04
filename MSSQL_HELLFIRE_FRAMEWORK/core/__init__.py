# core/__init__.py
from .scanner import AdvancedScanner
from .exploit import VulnerabilityExploiter  # Mantém o original
from .mssql_exploit import MSSQLExploiter    # Adiciona o novo
from .brute_force import MSSQLBruteForcer
from .post_exploit import PostExploitation
from .utils import AdvancedUtils

__all__ = [
    'AdvancedScanner',
    'VulnerabilityExploiter',  # Mantém
    'MSSQLExploiter',          # Adiciona
    'MSSQLBruteForcer',
    'PostExploitation', 
    'AdvancedUtils'
]