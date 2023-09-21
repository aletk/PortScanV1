from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, ICMP, sr1, TCP
import logging
import IpDetect.GerarListIps as lst
logging.basicConfig(level=logging.DEBUG)


class PingScan(lst.GerarListIps):
    """_PingScan_
    Classe para realizar o scan de um determinado host ou rede.
    """

    FLAG: str = "S"
    DEFAULT_PORT: [int] = [80, 443, 22, 21, 20, 25, 53, 110, 143, 445, 3389]
    TIMEOUT: int = 1
    VERBOSE: int = 0

    def __init__(self, ip: str) -> None:
        super().__init__(ip)

    def ScanIcmp(self, ipdest: str) -> None:
        """_scanIcmp_
        Método que realiza um ping em todos os endereços de um determinado host    
        """
        try:
            packet = IP(dst=ipdest) / ICMP(type="echo-request")
            response = sr1(packet, timeout=1, verbose=0)

            if response:
                self.HandleIcmpResponse(response)
        except Exception as e:
            logging.error(f"Erro ao escanear {ipdest} com ICMP: {e}")

    def ScanArp(self, ipDest: str) -> None:
        """_scanArp_
        Método que faz uma busca na tabela arp para verificar se o host está online ou não trazendo junto meu MAC address 
        """
        try:
            arp_packet = ARP(pdst=ipDest)
            response = sr1(arp_packet, timeout=self.TIMEOUT,
                           verbose=self.VERBOSE)

            if response:
                self.HandleArpResponse(response)
        except Exception as e:
            logging.error(f"Erro ao escanear {ipDest} com ARP: {e}")

    def ScanTcp(self, ipDest: tuple):
        """_scanTcp_
        Portas Default: [80 : HTTP, 443 : HTTPS, 22 : SSH, 21 : FTP, 20 : FTP, 25 : SMTP, 53 : DNS, 110 : POP3, 143 : IMAP, 445 : SMB, 3389 : RDP]
        """
        try:
            packet_tcp = IP(dst=ipDest[0]) / \
                TCP(dport=ipDest[1], flags=self.FLAG)
            response_tcp = sr1(packet_tcp, timeout=1, verbose=0)
            if response_tcp:
                self.HandleSynScanTcp(response_tcp)
        except Exception as e:
            logging.error(
                f"Erro ao escanear {ipDest}:{ipDest[1]} com TCP: {e}")

    def GetSO(self, ttl):

        if ttl in range(27, 33):
            return "Windows 95/98"
        elif ttl in range(123, 129):
            return "Windows 7/8/10/11"
        elif ttl in range(60, 66):
            return "Unix/Linux/Mac"
        elif ttl in range(240, 256):
            return "Linux/Mac"
        return f"SO not detect{str(ttl)}"

    def HandleIcmpResponse(self, response: str) -> str:
        """_HandleResponse_
        funções responsaveis por tratar o retorno das respostas 
        """
        print(
            f"[+] Host {response[IP].src} está ativo (IP: {response[IP].dst}) (SO: {self.GetSO(response[IP].ttl)})")

    def HandleArpResponse(self, response: str) -> str:
        print(
            f"[+] ARP resposta de {response[ARP].psrc}, MAC: {response[ARP].hwsrc} (SO: {self.GetSO(response[IP].ttl)})")

    def HandleSynScanTcp(self, response: str) -> str:
        if response[TCP].flags == "SA":
            print(
                f"[+] Porta Aberta : {response[TCP].sport}, IP: {response[IP].src} (SO: {self.GetSO(response[IP].ttl)})")
