# core/scanner.py
import socket
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed

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

class AdvancedScanner:
    def __init__(self):
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
            1434: 'MSSQL Browser', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 27017: 'MongoDB',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8888: 'HTTP-Alt2'
        }

    def identify_service(self, port):
        """Identifica serviço pela porta"""
        return self.common_ports.get(port, 'Unknown')

    def scan_port(self, target, port):
        """Escaneia uma porta específica - RETORNA TUPLA OU NONE"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = self.identify_service(port)
                    return (port, service)  # ✅ RETORNA TUPLA (port, service)
        except:
            pass
        return None

    def advanced_port_scan(self, target, ports=None):
        """Varredura de portas com threading - RETORNA LISTA DE TUPLAS"""
        if ports is None:
            ports = list(self.common_ports.keys())
        
        open_ports = []
        
        print(f"{Color.YELLOW}[+] Varrendo portas em {target}...{Color.END}")
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self.scan_port, target, port): port for port in ports}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    print(f"{Color.GREEN}[+] Porta {result[0]} aberta: {result[1]}{Color.END}")
        
        return open_ports  # ✅ RETORNA LISTA DE TUPLAS [(port, service), ...]

    def check_mssql_port(self, ip, port=1433, timeout=3):
        """Verifica se a porta MSSQL está aberta"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def quick_scan(self, target, common_only=True):
        """Scan rápido das portas mais comuns"""
        if common_only:
            ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 
                            443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080]
        else:
            ports_to_scan = list(self.common_ports.keys())
        
        return self.advanced_port_scan(target, ports_to_scan)

    def service_version_detection(self, target, port):
        """Tenta detectar a versão do serviço"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            
            # Envia dados básicos para elicitar resposta
            if port in [80, 443, 8080, 8443]:
                sock.send(b'GET / HTTP/1.0\r\n\r\n')
            elif port == 21:
                sock.send(b'USER anonymous\r\n')
            elif port == 25:
                sock.send(b'EHLO example.com\r\n')
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return banner.strip()[:500]  # Retorna primeiros 500 chars
            
        except:
            return "Unable to retrieve banner"