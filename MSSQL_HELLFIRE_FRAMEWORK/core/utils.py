# core/utils.py
import socket
import dns.resolver
import ipaddress
import geoip2.database
import ssl
import cryptography
from cryptography.fernet import Fernet
import hashlib
import base64
import json
import xml.etree.ElementTree as ET
import yaml
import tomllib
import configparser
import pickle
import marshal
import zlib
import gzip
import brotli
import lzma

class AdvancedUtils:
    def __init__(self):
        self.geoip_reader = None
        try:
            self.geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        except:
            pass

    def get_domain_info(self, target):
        """Obtém informações do domínio"""
        try:
            # Tenta resolver IP para domínio
            try:
                domain = socket.gethostbyaddr(target)[0]
            except:
                domain = target
            
            # DNS lookup
            info = {
                'domain': domain,
                'ip': target,
                'mx_records': [],
                'ns_records': [],
                'txt_records': []
            }
            
            # MX Records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                info['mx_records'] = [str(record.exchange) for record in mx_records]
            except:
                pass
            
            # NS Records
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                info['ns_records'] = [str(record) for record in ns_records]
            except:
                pass
            
            # TXT Records
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                info['txt_records'] = [str(record) for record in txt_records]
            except:
                pass
            
            # GeoIP
            if self.geoip_reader:
                try:
                    response = self.geoip_reader.city(target)
                    info['geoip'] = {
                        'country': response.country.name,
                        'city': response.city.name,
                        'latitude': response.location.latitude,
                        'longitude': response.location.longitude
                    }
                except:
                    pass
            
            return info
            
        except Exception as e:
            return {'error': str(e)}

    def advanced_encrypt(self, data, key=None):
        """Criptografia avançada"""
        if not key:
            key = Fernet.generate_key()
        
        cipher = Fernet(key)
        if isinstance(data, dict):
            data = json.dumps(data)
        
        encrypted = cipher.encrypt(data.encode())
        return encrypted, key

    def advanced_decrypt(self, encrypted_data, key):
        """Descriptografia avançada"""
        cipher = Fernet(key)
        decrypted = cipher.decrypt(encrypted_data)
        return decrypted.decode()

    def hash_data(self, data, algorithm='sha256'):
        """Gera hash de dados"""
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

    def network_utils(self, target):
        """Utilitários de rede avançados"""
        try:
            # WHOIS simulado
            info = {
                'ip': target,
                'network': str(ipaddress.ip_network(target + '/24', strict=False)),
                'is_private': ipaddress.ip_address(target).is_private,
                'reverse_dns': socket.gethostbyaddr(target)[0] if not ipaddress.ip_address(target).is_private else 'N/A'
            }
            
            # Portas comuns
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                          993, 995, 1433, 3306, 3389, 5432, 8080]
            
            open_ports = []
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            
            info['open_ports'] = open_ports
            return info
            
        except Exception as e:
            return {'error': str(e)}

    def ssl_info(self, target, port=443):
        """Informações SSL/TLS"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'version': cert['version'],
                        'serialNumber': cert['serialNumber'],
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter'],
                        'cipher': ssock.cipher()
                    }
                    
                    return ssl_info
                    
        except Exception as e:
            return {'error': str(e)}

    def data_serialization(self, data, format_type='json'):
        """Serialização de dados em múltiplos formatos"""
        if format_type == 'json':
            return json.dumps(data)
        elif format_type == 'xml':
            root = ET.Element("data")
            for key, value in data.items():
                child = ET.SubElement(root, key)
                child.text = str(value)
            return ET.tostring(root, encoding='unicode')
        elif format_type == 'yaml':
            return yaml.dump(data)
        elif format_type == 'pickle':
            return pickle.dumps(data)
        elif format_type == 'messagepack':
            return marshal.dumps(data)
        else:
            return json.dumps(data)

    def data_deserialization(self, data, format_type='json'):
        """Desserialização de dados"""
        if format_type == 'json':
            return json.loads(data)
        elif format_type == 'xml':
            root = ET.fromstring(data)
            return {child.tag: child.text for child in root}
        elif format_type == 'yaml':
            return yaml.safe_load(data)
        elif format_type == 'pickle':
            return pickle.loads(data)
        elif format_type == 'messagepack':
            return marshal.loads(data)
        else:
            return json.loads(data)