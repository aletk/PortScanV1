import IpDetect.GerarListIps as lst
from concurrent.futures import ThreadPoolExecutor
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, ICMP, sr1, TCP
import logging
import ipwhois

"""_PingScan_
Classe para realizar o scan de um determinado host ou rede.
"""


class PingScan(lst.GerarListIps):

    MAX_THREADS: int = 40
    FLAG: str = "S"
    DEFAULT_PORT: [int] = [80, 443, 22, 21, 20, 25, 53, 110, 143, 445, 3389]
    TIMEOUT: int = 1
    VERBOSE: int = 0

    def __init__(self, ip: str) -> None:
        super().__init__(ip)

    """_scanIcmp_
    Método que realiza um ping em todos os endereços de um determinado host    
    """

    def ScanIcmp(self, ipdest: str) -> None:
        try:
            packet = IP(dst=ipdest) / ICMP(type="echo-request")
            response = sr1(packet, timeout=1, verbose=0)

            if response:
                self.HandleIcmpResponse(response)
        except Exception as e:
            logging.error(f"Erro ao escanear {ipdest} com ICMP: {e}")

    """_scanArp_
    Método que faz uma busca na tabela arp para verificar se o host está online ou não trazendo junto meu MAC address 
    """

    def ScanArp(self, ipDest: str) -> None:

        try:
            arp_packet = ARP(pdst=ipDest)
            response = sr1(arp_packet, timeout=self.TIMEOUT,
                           verbose=self.VERBOSE)

            if response:
                self.HandleArpResponse(response)
        except Exception as e:
            logging.error(f"Erro ao escanear {ipDest} com ARP: {e}")

    """_scanTcp_
    Portas Default: [80 : HTTP, 443 : HTTPS, 22 : SSH, 21 : FTP, 20 : FTP, 25 : SMTP, 53 : DNS, 110 : POP3, 143 : IMAP, 445 : SMB, 3389 : RDP]
    """

    def ScanTcp(self, ipDest: tuple):
        try:
            packet_tcp = IP(dst=ipDest[0]) / \
                TCP(dport=ipDest[1], flags=self.FLAG)
            response_tcp = sr1(packet_tcp, timeout=1, verbose=0)
            if response_tcp:
                self.HandleSynScanTcp(response_tcp)
        except Exception as e:
            logging.error(
                f"Erro ao escanear {ipDest}:{ipDest[1]} com TCP: {e}")

    """_ExecuteScan_
    Método responsável por executar o método correspondente a cada protocolo escolhido pelo usuário para realizar uma varredura no target
    """

    def ExecuteScan(self, typeScan: str) -> None:
        try:
            if "icmp" in typeScan:
                scanner = self.ScanIcmp
            elif "arp" in typeScan:
                scanner = self.ScanArp
            elif "tcp" in typeScan:
                scanner = self.ScanTcp
                self.IpList = [(ip, porta)
                               for ip in self.IpList for porta in self.DEFAULT_PORT]
            else:
                raise ValueError("Tipo de scan não suportado.")

            with ThreadPoolExecutor(max_workers=self.MAX_THREADS) as executor:
                executor.map(scanner, self.IpList)
        except Exception as e:
            logging.error(f"Erro durante a execução do scan: {e}")

    """_HandleResponse_
    funções responsaveis por tratar o retorno das respostas 
    """

    def GetSO(self, ttl):

        if ttl == 32:
            return "Windows 95/98"
        elif ttl == 128:
            return "Windows 7/8/10/11"
        elif ttl == 64:
            return "Unix/Linux/Mac"
        return "SO not detect"

    def HandleIcmpResponse(self, response):
        print(
            f"[+] Host {response[IP].src} está ativo (IP: {response[IP].dst}) (SO: {self.GetSO(response[IP].ttl)})")

    def HandleArpResponse(self, response):
        print(
            f"[+] ARP resposta de {response[ARP].psrc}, MAC: {response[ARP].hwsrc} (SO: {self.GetSO(response[IP].ttl)})")

    def HandleSynScanTcp(self, response):
        if response[TCP].flags == "SA":
            print(
                f"[+] Porta Aberta : {response[TCP].sport}, IP: {response[IP].src} (SO: {self.GetSO(response[IP].ttl)})")
