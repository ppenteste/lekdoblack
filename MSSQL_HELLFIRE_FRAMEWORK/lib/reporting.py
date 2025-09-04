# lib/reporting.py
import json
import csv
import html
import xml.etree.ElementTree as ET
from datetime import datetime
import os
from .encryption import EncryptionUtils

class ReportGenerator:
    def __init__(self):
        self.encryption = EncryptionUtils()
    
    def generate_json_report(self, data, filename):
        """Gera relatório em JSON"""
        report = {
            'scan_date': datetime.now().isoformat(),
            'results': data,
            'summary': self._generate_summary(data)
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return filename
    
    def generate_html_report(self, data, filename):
        """Gera relatório em HTML"""
        html_content = f"""
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Relatório de Scan - MSSQL Hellfire Framework</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #0d1117; color: #c9d1d9; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .header {{ background: #161b22; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                .section {{ background: #161b22; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                .vulnerability {{ background: #f85149; color: white; padding: 10px; margin: 5px 0; border-radius: 3px; }}
                .warning {{ background: #d29922; color: white; padding: 10px; margin: 5px 0; border-radius: 3px; }}
                .success {{ background: #3fb950; color: white; padding: 10px; margin: 5px 0; border-radius: 3px; }}
                .info {{ background: #58a6ff; color: white; padding: 10px; margin: 5px 0; border-radius: 3px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #30363d; }}
                th {{ background: #161b22; }}
                pre {{ background: #161b22; padding: 15px; border-radius: 5px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔓 Relatório de Scan - MSSQL Hellfire Framework</h1>
                    <p>Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
                </div>
                
                <div class="section">
                    <h2>📊 Resumo Executivo</h2>
                    {self._generate_html_summary(data)}
                </div>
                
                <div class="section">
                    <h2>🎯 Resultados Detalhados</h2>
                    {self._generate_html_details(data)}
                </div>
                
                <div class="section">
                    <h2>⚠️ Vulnerabilidades</h2>
                    {self._generate_html_vulnerabilities(data)}
                </div>
                
                <div class="section">
                    <h2>🔑 Credenciais Encontradas</h2>
                    {self._generate_html_credentials(data)}
                </div>
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filename
    
    def generate_csv_report(self, data, filename):
        """Gera relatório em CSV"""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Escreve cabeçalho
            writer.writerow(['Target', 'Type', 'Data', 'Severity', 'Timestamp'])
            
            # Escreve dados
            for target, results in data.get('targets', {}).items():
                # Vulnerabilidades
                for vuln in results.get('vulnerabilities', []):
                    writer.writerow([target, 'VULNERABILITY', vuln, 'HIGH', datetime.now().isoformat()])
                
                # Credenciais
                for cred in results.get('credentials', []):
                    if isinstance(cred, tuple) and len(cred) == 2:
                        writer.writerow([target, 'CREDENTIAL', f"{cred[0]}:{cred[1]}", 'CRITICAL', datetime.now().isoformat()])
                
                # Portas abertas
                for port, service in results.get('open_ports', []):
                    writer.writerow([target, 'OPEN_PORT', f"{port}/{service}", 'INFO', datetime.now().isoformat()])
        
        return filename
    
    def generate_encrypted_report(self, data, filename, password=None):
        """Gera relatório criptografado"""
        json_report = self.generate_json_report(data, filename + '.tmp')
        
        with open(json_report, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        
        encrypted_file, key = self.encryption.encrypt_file(json_report)
        os.remove(json_report)
        
        # Salva metadados
        metadata = {
            'encrypted_file': encrypted_file,
            'encryption_date': datetime.now().isoformat(),
            'key_hash': self.encryption.hash_data(key.decode())
        }
        
        with open(filename + '.meta', 'w') as f:
            json.dump(metadata, f, indent=2)
        
        return encrypted_file, key
    
    def _generate_summary(self, data):
        """Gera resumo dos resultados"""
        total_targets = len(data.get('targets', {}))
        total_vulnerabilities = 0
        total_credentials = 0
        total_ports = 0
        
        for target_results in data.get('targets', {}).values():
            total_vulnerabilities += len(target_results.get('vulnerabilities', []))
            total_credentials += len(target_results.get('credentials', []))
            total_ports += len(target_results.get('open_ports', []))
        
        return {
            'total_targets': total_targets,
            'total_vulnerabilities': total_vulnerabilities,
            'total_credentials': total_credentials,
            'total_open_ports': total_ports,
            'scan_date': datetime.now().isoformat()
        }
    
    def _generate_html_summary(self, data):
        """Gera resumo em HTML"""
        summary = self._generate_summary(data)
        return f"""
        <div class="info">
            <strong>Alvos Escaneados:</strong> {summary['total_targets']}
        </div>
        <div class="vulnerability">
            <strong>Vulnerabilidades Encontradas:</strong> {summary['total_vulnerabilities']}
        </div>
        <div class="success">
            <strong>Credenciais Comprometidas:</strong> {summary['total_credentials']}
        </div>
        <div class="warning">
            <strong>Portas Abertas:</strong> {summary['total_open_ports']}
        </div>
        """
    
    def _generate_html_details(self, data):
        """Gera detalhes em HTML"""
        details_html = ""
        for target, results in data.get('targets', {}).items():
            details_html += f"""
            <div class="info">
                <h3>🎯 Target: {target}</h3>
                <p><strong>Portas Abertas:</strong> {len(results.get('open_ports', []))}</p>
                <p><strong>Vulnerabilidades:</strong> {len(results.get('vulnerabilities', []))}</p>
                <p><strong>Credenciais:</strong> {len(results.get('credentials', []))}</p>
            </div>
            """
        return details_html
    
    def _generate_html_vulnerabilities(self, data):
        """Gera vulnerabilidades em HTML"""
        vulns_html = ""
        for target, results in data.get('targets', {}).items():
            for vuln in results.get('vulnerabilities', []):
                vulns_html += f"""
                <div class="vulnerability">
                    <strong>{target}:</strong> {html.escape(str(vuln))}
                </div>
                """
        return vulns_html if vulns_html else "<div class='info'>Nenhuma vulnerabilidade crítica encontrada.</div>"
    
    def _generate_html_credentials(self, data):
        """Gera credenciais em HTML"""
        creds_html = ""
        for target, results in data.get('targets', {}).items():
            for cred in results.get('credentials', []):
                if isinstance(cred, tuple) and len(cred) == 2:
                    creds_html += f"""
                    <div class="success">
                        <strong>{target}:</strong> {html.escape(cred[0])}:{html.escape(cred[1])}
                    </div>
                    """
        return creds_html if creds_html else "<div class='info'>Nenhuma credencial encontrada.</div>"