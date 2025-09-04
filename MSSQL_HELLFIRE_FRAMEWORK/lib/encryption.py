# lib/encryption.py
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import json
import pickle

class EncryptionUtils:
    def __init__(self):
        self.encryption_key = None
        
    def generate_key(self, password=None, salt=None):
        """Gera chave de criptografia"""
        if password:
            if salt is None:
                salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            return key, salt
        else:
            return Fernet.generate_key(), None
    
    def encrypt_data(self, data, key=None):
        """Criptografa dados"""
        if key is None:
            key = Fernet.generate_key()
        
        if isinstance(data, dict):
            data = json.dumps(data)
        
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data.encode())
        return encrypted_data, key
    
    def decrypt_data(self, encrypted_data, key):
        """Descriptografa dados"""
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        
        # Tenta decodificar como JSON, senão retorna string
        try:
            return json.loads(decrypted_data.decode())
        except:
            return decrypted_data.decode()
    
    def hash_data(self, data, algorithm='sha256'):
        """Gera hash de dados"""
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True)
        
        if algorithm == 'md5':
            return hashlib.md5(data.encode()).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(data.encode()).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(data.encode()).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(data.encode()).hexdigest()
        else:
            return hashlib.sha256(data.encode()).hexdigest()
    
    def encrypt_file(self, file_path, key=None):
        """Criptografa arquivo"""
        if key is None:
            key = Fernet.generate_key()
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)
        
        encrypted_file = file_path + '.encrypted'
        with open(encrypted_file, 'wb') as f:
            f.write(encrypted_data)
        
        return encrypted_file, key
    
    def decrypt_file(self, encrypted_file, key, output_file=None):
        """Descriptografa arquivo"""
        if output_file is None:
            output_file = encrypted_file.replace('.encrypted', '')
        
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()
        
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
        
        return output_file
    
    def create_secure_backup(self, data, backup_path, password=None):
        """Cria backup seguro criptografado"""
        if password:
            key, salt = self.generate_key(password)
        else:
            key, salt = self.generate_key()
        
        encrypted_data, _ = self.encrypt_data(data, key)
        
        backup_data = {
            'data': encrypted_data.decode(),
            'salt': base64.b64encode(salt).decode() if salt else None,
            'algorithm': 'AES-256'
        }
        
        with open(backup_path, 'w') as f:
            json.dump(backup_data, f)
        
        return key
    
    def load_secure_backup(self, backup_path, key=None, password=None):
        """Carrega backup seguro"""
        with open(backup_path, 'r') as f:
            backup_data = json.load(f)
        
        encrypted_data = backup_data['data'].encode()
        salt = base64.b64decode(backup_data['salt']) if backup_data['salt'] else None
        
        if key is None and password:
            key, _ = self.generate_key(password, salt)
        
        return self.decrypt_data(encrypted_data, key)