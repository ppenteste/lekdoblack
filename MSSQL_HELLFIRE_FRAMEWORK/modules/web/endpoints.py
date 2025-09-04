# modules/web/endpoints.py
import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
import re
import random

class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class EndpointDiscoverer:
    def __init__(self):
        self.common_endpoints = self.load_endpoints()
        self.common_files = self.load_common_files()
        self.tested_endpoints = set()
        
    def load_endpoints(self):
        """Carrega endpoints comuns"""
        try:
            with open('wordlists/endpoints.txt', 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except:
            return [
                '/', '/admin', '/login', '/logout', '/register', '/signup',
                '/api', '/api/v1', '/api/v2', '/graphql', '/rest', '/soap',
                '/config', '/debug', '/test', '/info', '/phpinfo', '/status',
                '/health', '/metrics', '/console', '/manager', '/webadmin',
                '/administrator', '/phpmyadmin', '/mysql', '/pma', '/wp-admin',
                '/wp-login', '/server-status', '/server-info', '/robots.txt',
                '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml',
                '/.env', '/.git/config', '/.svn/entries', '/.htaccess',
                '/web.config', '/config.json', '/config.xml', '/backup',
                '/backups', '/old', '/new', '/temp', '/tmp', '/upload',
                '/uploads', '/download', '/downloads', '/files', '/images',
                '/img', '/css', '/js', '/static', '/media', '/cpanel',
                '/whm', '/webmail', '/mail', '/email', '/owa', '/exchange',
                '/sharepoint', '/vpn', '/remote', '/rdp', '/ssh', '/ftp',
                '/telnet', '/shell', '/cmd', '/command', '/exec', '/system'
            ]

    def load_common_files(self):
        """Carrega arquivos comuns"""
        return [
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
            '/clientaccesspolicy.xml', '/security.txt', '/humans.txt',
            '/.well-known/security.txt', '/.git/HEAD', '/.svn/entries',
            '/.env', '/.htaccess', '/web.config', '/config.php',
            '/settings.py', '/package.json', '/composer.json'
        ]

    def get_random_headers(self):
        """Gera headers aleatórios"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        ]
        return {
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    def discover_endpoints(self, base_url):
        """Descobre endpoints em um alvo - RETORNA LISTA DE TUPLAS"""
        discovered = []
        
        print(f"{Color.YELLOW}[+] Procurando endpoints em {base_url}...{Color.END}")
        
        def test_endpoint(endpoint):
            full_url = urljoin(base_url, endpoint)
            if full_url not in self.tested_endpoints:
                self.tested_endpoints.add(full_url)
                try:
                    response = requests.get(full_url, timeout=5, verify=False, 
                                          headers=self.get_random_headers(),
                                          allow_redirects=True)
                    if response.status_code < 400:  # Considera 2xx e 3xx
                        discovered.append((full_url, response.status_code))
                        print(f"{Color.GREEN}[+] Endpoint: {full_url} ({response.status_code}){Color.END}")
                        return True
                except:
                    pass
            return False
        
        # Testa endpoints comuns
        for endpoint in self.common_endpoints:
            test_endpoint(endpoint)
        
        # Testa arquivos comuns
        for file_path in self.common_files:
            test_endpoint(file_path)
        
        return discovered  # ✅ RETORNA LISTA DE TUPLAS (url, status)

    def test_common_files(self, base_url):
        """Testa arquivos comuns - RETORNA LISTA DE TUPLAS"""
        found_files = []
        
        for file_path in self.common_files:
            full_url = urljoin(base_url, file_path)
            try:
                response = requests.get(full_url, timeout=5, verify=False)
                if response.status_code == 200 and len(response.text) > 0:
                    found_files.append((full_url, response.status_code))
                    print(f"{Color.GREEN}[+] Arquivo: {full_url} ({response.status_code}){Color.END}")
                    
            except:
                continue
                
        return found_files  # ✅ RETORNA LISTA DE TUPLAS

    def crawl_website(self, base_url, max_depth=2):
        """Crawling básico do website - RETORNA LISTA DE URLs"""
        crawled_urls = set()
        to_crawl = [(base_url, 0)]
        
        while to_crawl:
            url, depth = to_crawl.pop(0)
            
            if depth > max_depth or url in crawled_urls:
                continue
                
            try:
                response = requests.get(url, timeout=8, verify=False)
                crawled_urls.add(url)
                
                # Extrai links da página
                links = re.findall(r'href=[\'"]?([^\'" >]+)', response.text, re.IGNORECASE)
                
                for link in links:
                    absolute_url = urljoin(url, link)
                    if base_url in absolute_url and absolute_url not in crawled_urls:
                        to_crawl.append((absolute_url, depth + 1))
                        print(f"{Color.GREEN}[+] Link encontrado: {absolute_url}{Color.END}")
                        
            except:
                continue
                
        return list(crawled_urls)