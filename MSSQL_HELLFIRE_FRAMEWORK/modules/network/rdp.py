# modules/network/rdp.py
import socket
import subprocess
import re

class RDPDetector:
    def __init__(self):
        self.common_ports = [3389, 3390, 3391]

    def check_rdp_port(self, target, port=3389):
        """Verifica se porta RDP está aberta"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            result = s.connect_ex((target, port))
            s.close()
            return result == 0
        except:
            return False

    def rdp_banner_grabbing(self, target, port=3389):
        """Banner grabbing RDP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, port))
            
            # RDP inicia com pacote específico
            banner = s.recv(1024)
            s.close()
            
            if banner:
                # Tenta decodificar o banner RDP
                try:
                    return banner.hex()[:50]  # Retorna primeiros bytes em hex
                except:
                    return "Binary data received"
        except:
            pass
        return "No banner"

    def check_rdp_vulnerabilities(self, target, port=3389):
        """Verifica vulnerabilidades RDP comuns"""
        vulnerabilities = []
        
        # Verifica BlueKeep (CVE-2019-0708)
        try:
            cmd = f"nmap -p {port} --script rdp-vuln-ms12-020 {target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if "VULNERABLE" in result.stdout:
                vulnerabilities.append("MS12-020 (BlueKeep)")
                
        except:
            pass
        
        return vulnerabilities

    def rdp_enumeration(self, target, port=3389):
        """Enumeração RDP básica"""
        info = {}
        
        # Tenta detectar se requer NLA
        try:
            cmd = f"nmap -p {port} --script rdp-ntlm-info {target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if "Network Level Authentication" in result.stdout:
                info['nla_required'] = True
            else:
                info['nla_required'] = False
                
            # Extrai informações NTLM
            ntlm_info = re.findall(r'([A-Za-z_]+): (.+)', result.stdout)
            for key, value in ntlm_info:
                info[key.lower()] = value.strip()
                
        except:
            info['nla_required'] = "Unknown"
        
        return info

    def brute_force_rdp(self, target, port=3389):
        """Força bruta RDP (conceitual)"""
        # Em produção, usar hydra ou outra tool
        print("[+] Brute force RDP requer ferramentas externas (hydra, crowbar)")
        return []

    def scan_rdp(self, target):
        """Scan completo RDP"""
        print(f"[+] Scan RDP em: {target}")
        
        results = {
            'ports_open': [],
            'banners': {},
            'vulnerabilities': [],
            'info': {}
        }
        
        # Verifica portas RDP
        for port in self.common_ports:
            if self.check_rdp_port(target, port):
                results['ports_open'].append(port)
                print(f"    [+] Porta {port} aberta")
                
                # Banner grabbing
                banner = self.rdp_banner_grabbing(target, port)
                results['banners'][port] = banner
                print(f"    [+] Banner: {banner}")
                
                # Verifica vulnerabilidades
                vulns = self.check_rdp_vulnerabilities(target, port)
                results['vulnerabilities'].extend(vulns)
                for vuln in vulns:
                    print(f"    [!] VULNERABILIDADE: {vuln}")
                
                # Enumeração
                info = self.rdp_enumeration(target, port)
                results['info'][port] = info
                print(f"    [+] Info: {info}")
        
        return results