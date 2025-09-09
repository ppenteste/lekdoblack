# config/settings.py
# -*- coding: utf-8 -*-
# [Lek Do BlacK] - CONFIGURAÇÕES PRINCIPAIS DO FRAMEWORK

import os
from datetime import datetime

class Config:
    def __init__(self):
        # Configurações básicas
        self.VERSION = "12.0"
        self.AUTHOR = "Lek Do BlacK"
        self.CREATION_DATE = "2024"
        
        # Configurações de rede
        self.TIMEOUT = 10
        self.MAX_THREADS = 100
        self.MAX_RETRIES = 3
        self.USER_AGENT_ROTATION = True
        
        # Configurações de scan
        self.PORTS_TO_SCAN = [
            # Portas web
            80, 443, 8080, 8443, 8888, 8000, 8008, 8088, 8090, 8180, 8280, 8380, 8480, 8580,
            8680, 8780, 8880, 8980, 9000, 9090, 9191, 9292, 9393, 9494, 9595, 9696, 9797, 9898, 9999,
            
            # Portas de banco de dados
            1433, 1434, 3306, 5432, 1521, 27017, 27018, 27019,
            
            # Portas de serviços
            21, 22, 23, 25, 53, 110, 135, 139, 143, 445, 993, 995, 3389,
            
            # Outras portas importantes
            161, 162, 389, 636, 989, 990, 2222, 2375, 2376, 3000, 5000, 5431, 5900, 6379, 9200, 11211
        ]
        
        # Configurações de brute force
        self.BRUTE_FORCE_ENABLED = True
        self.MAX_BRUTE_FORCE_ATTEMPTS = 1000
        self.BRUTE_FORCE_DELAY = 0.1
        
        # Configurações de proxy
        self.USE_PROXIES = True
        self.PROXY_TIMEOUT = 15
        self.PROXY_ROTATION = True
        
        # Configurações de evasão
        self.RANDOM_DELAY = True
        self.MIN_DELAY = 0.5
        self.MAX_DELAY = 3.0
        self.USE_TOR = False
        
        # Configurações de output
        self.SAVE_RESULTS = True
        self.VERBOSE_MODE = True
        self.COLOR_OUTPUT = True
        self.LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR
        
        # Configurações de segurança
        self.ENCRYPT_RESULTS = True
        self.CLEANUP_LOGS = True
        self.SELF_DESTRUCT = False
        
        # APIs e chaves (configure conforme necessário)
        self.SHODAN_API_KEY = ""
        self.VIRUSTOTAL_API_KEY = ""
        self.CENSYS_API_ID = ""
        self.CENSYS_API_SECRET = ""
        
        # Caminhos dos arquivos
        self.BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.WORDLISTS_DIR = os.path.join(self.BASE_DIR, "wordlists")
        self.RESULTS_DIR = os.path.join(self.BASE_DIR, "results")
        self.LOGS_DIR = os.path.join(self.BASE_DIR, "logs")
        self.CONFIG_DIR = os.path.join(self.BASE_DIR, "config")
        
        # Arquivos específicos
        self.PROXIES_FILE = os.path.join(self.CONFIG_DIR, "proxies.txt")
        self.USER_AGENTS_FILE = os.path.join(self.CONFIG_DIR, "user_agents.txt")
        self.IPS_FILE = os.path.join(self.BASE_DIR, "ips.txt")
        
        # Wordlists
        self.USER_WORDLIST = os.path.join(self.WORDLISTS_DIR, "usuarios.txt")
        self.PASS_WORDLIST = os.path.join(self.WORDLISTS_DIR, "senhas.txt")
        self.ENDPOINTS_WORDLIST = os.path.join(self.WORDLISTS_DIR, "endpoints.txt")
        
        # Payloads
        self.XSS_PAYLOADS = os.path.join(self.WORDLISTS_DIR, "payloads", "xss.txt")
        self.SQLI_PAYLOADS = os.path.join(self.WORDLISTS_DIR, "payloads", "sqli.txt")
        self.LFI_PAYLOADS = os.path.join(self.WORDLISTS_DIR, "payloads", "lfi.txt")
        
        # Criar diretórios se não existirem
        self._create_directories()
    
    def _create_directories(self):
        """Cria os diretórios necessários"""
        os.makedirs(self.WORDLISTS_DIR, exist_ok=True)
        os.makedirs(self.RESULTS_DIR, exist_ok=True)
        os.makedirs(self.LOGS_DIR, exist_ok=True)
        os.makedirs(self.CONFIG_DIR, exist_ok=True)
        os.makedirs(os.path.join(self.WORDLISTS_DIR, "payloads"), exist_ok=True)
    
    def get_config(self):
        """Retorna todas as configurações"""
        return {
            'version': self.VERSION,
            'author': self.AUTHOR,
            'timeout': self.TIMEOUT,
            'max_threads': self.MAX_THREADS,
            'ports_to_scan': self.PORTS_TO_SCAN,
            'brute_force_enabled': self.BRUTE_FORCE_ENABLED,
            'use_proxies': self.USE_PROXIES,
            'random_delay': self.RANDOM_DELAY,
            'save_results': self.SAVE_RESULTS,
            'verbose_mode': self.VERBOSE_MODE,
            'encrypt_results': self.ENCRYPT_RESULTS
        }
    
    def update_setting(self, key, value):
        """Atualiza uma configuração"""
        if hasattr(self, key):
            setattr(self, key, value)
            return True
        return False

# Instância global de configuração

config = Config()
