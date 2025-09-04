# lib/evasion.py
import random
import time
from urllib.parse import urlparse, quote, unquote
import base64
import hashlib
import string

class EvasionTechniques:
    def __init__(self):
        self.obfuscation_methods = [
            'base64', 'url', 'unicode', 'hex', 'html', 'double_url',
            'upper', 'lower', 'random_case', 'comment', 'whitespace'
        ]
        
        self.user_agents = [
            # Lista de user agents será carregada do config
        ]
    
    def rotate_user_agent(self):
        """Rotaciona User-Agent"""
        if not self.user_agents:
            # User agents padrão se não carregados
            return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        
        return random.choice(self.user_agents)
    
    def random_delay(self, min_delay=0.5, max_delay=3.0):
        """Adiciona delay aleatório entre requests"""
        delay = random.uniform(min_delay, max_delay)
        time.sleep(delay)
        return delay
    
    def obfuscate_payload(self, payload, method=None):
        """Obfusca payload para bypass de WAF"""
        if method is None:
            method = random.choice(self.obfuscation_methods)
        
        if method == 'base64':
            return base64.b64encode(payload.encode()).decode()
        
        elif method == 'url':
            return quote(payload)
        
        elif method == 'unicode':
            return ''.join([f'%u{ord(c):04x}' for c in payload])
        
        elif method == 'hex':
            return ''.join([f'%{ord(c):02x}' for c in payload])
        
        elif method == 'html':
            return ''.join([f'&#{ord(c)};' for c in payload])
        
        elif method == 'double_url':
            return quote(quote(payload))
        
        elif method == 'upper':
            return payload.upper()
        
        elif method == 'lower':
            return payload.lower()
        
        elif method == 'random_case':
            return ''.join(random.choice([c.upper(), c.lower()]) for c in payload)
        
        elif method == 'comment':
            # Adiciona comentários aleatórios
            comments = ['/**/', '/*!*/', '/*!50000*/', '/*!12345*/']
            parts = []
            for char in payload:
                if random.random() > 0.8:
                    parts.append(random.choice(comments))
                parts.append(char)
            return ''.join(parts)
        
        elif method == 'whitespace':
            # Adiciona whitespace aleatório
            whitespace = ['%09', '%0A', '%0C', '%0D', '%20', '%A0']
            parts = []
            for char in payload:
                if random.random() > 0.7:
                    parts.append(random.choice(whitespace))
                parts.append(char)
            return ''.join(parts)
        
        return payload
    
    def generate_random_ip(self):
        """Gera IP aleatório para headers"""
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    
    def get_evasive_headers(self):
        """Gera headers evasivos"""
        return {
            'User-Agent': self.rotate_user_agent(),
            'X-Forwarded-For': self.generate_random_ip(),
            'X-Real-IP': self.generate_random_ip(),
            'X-Client-IP': self.generate_random_ip(),
            'X-Originating-IP': self.generate_random_ip(),
            'X-Remote-IP': self.generate_random_ip(),
            'X-Remote-Addr': self.generate_random_ip(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': random.choice(['en-US,en;q=0.5', 'pt-BR,pt;q=0.8', 'es-ES,es;q=0.6']),
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': random.choice(['keep-alive', 'close', 'upgrade']),
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': random.choice(['max-age=0', 'no-cache', 'no-store']),
            'Pragma': 'no-cache',
            'TE': 'Trailers'
        }
    
    def domain_fronting_url(self, url, cdn_domain='cloudfront.net'):
        """Simula domain fronting"""
        parsed = urlparse(url)
        original_domain = parsed.netloc
        
        # Substitui o domínio por um de CDN
        fronted_url = url.replace(original_domain, cdn_domain)
        
        # Adiciona header Host com domínio original
        headers = self.get_evasive_headers()
        headers['Host'] = original_domain
        
        return fronted_url, headers
    
    def fragment_request(self, url, data=None):
        """Fragmenta request em partes"""
        # Implementação básica de fragmentação
        parsed = urlparse(url)
        
        # Quebra URL em partes
        fragments = []
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        if parsed.query:
            queries = parsed.query.split('&')
            for i, query in enumerate(queries):
                fragment_url = f"{base_url}?{query}"
                if i < len(queries) - 1:
                    fragment_url += "&" + "&".join(queries[i+1:])
                fragments.append(fragment_url)
        else:
            fragments.append(base_url)
        
        return fragments
    
    def timestamp_obfuscation(self, payload):
        """Adiciona timestamps para evitar detecção"""
        timestamp = str(int(time.time()))
        return f"{payload}&_={timestamp}"
    
    def checksum_obfuscation(self, payload):
        """Adiciona checksum para bypass"""
        checksum = hashlib.md5(payload.encode()).hexdigest()[:8]
        return f"{payload}&checksum={checksum}"
    
    def case_permutation(self, payload):
        """Gera permutações de case para bypass"""
        permutations = []
        for i in range(3):  # Gera 3 variações
            permuted = ''.join(random.choice([c.upper(), c.lower()]) for c in payload)
            permutations.append(permuted)
        return permutations
    
    def encoding_permutation(self, payload):
        """Gera diferentes encodings do mesmo payload"""
        encodings = []
        
        # URL encoding
        encodings.append(quote(payload))
        
        # Double URL encoding
        encodings.append(quote(quote(payload)))
        
        # Unicode encoding
        unicode_encoded = ''.join([f'%u{ord(c):04x}' for c in payload])
        encodings.append(unicode_encoded)
        
        # HTML encoding
        html_encoded = ''.join([f'&#{ord(c)};' for c in payload])
        encodings.append(html_encoded)
        
        return encodings
    
    def advanced_obfuscation(self, payload, level=3):
        """Obfuscação avançada com múltiplas técnicas"""
        obfuscated = payload
        
        for _ in range(level):
            method = random.choice(self.obfuscation_methods)
            obfuscated = self.obfuscate_payload(obfuscated, method)
            
            # Adiciona técnicas adicionais com certa probabilidade
            if random.random() > 0.5:
                obfuscated = self.timestamp_obfuscation(obfuscated)
            if random.random() > 0.5:
                obfuscated = self.checksum_obfuscation(obfuscated)
        
        return obfuscated