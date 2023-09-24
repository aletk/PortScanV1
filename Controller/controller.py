from concurrent.futures import ThreadPoolExecutor
import logging
from IpDetect.PingScan import PingScan
from Rdap.rdap import ConsultaRdap
logging.basicConfig(level=logging.DEBUG)


class Constroller():

    def __init__(self, typeConsult: str, ip: str, maxThread) -> None:
        self.Threads = maxThread
        self.Ip: str = ip
        self.TypeConsult: str = typeConsult

    def ExecuteConsult(self) -> None:

        if self.TypeConsult == "whois":
            self.ExecuteConsultWhois()
        elif self.TypeConsult in ["icmp", "arp", "tcp"]:
            self.ExecuteScan(self.TypeConsult)
        else:
            raise ValueError("Tipo de consulta não suportado.")

    def ExecuteConsultWhois(self):
        """_ExecuteConsultWhois_
        Método responsável por executar uma consulta Rdap no ip passado 
        """
        try:
            whois = ConsultaRdap(self.Ip)
            with ThreadPoolExecutor(max_workers=self.Threads) as executor:
                executor.map(whois.ConsultRdap, whois.IpList)
            whois.ConsultRdap()
        except Exception as e:
            logging.error(f"Erro durante a execução do scan: {e}")

    def ExecuteScan(self, typeScan: str) -> None:
        pingScan = PingScan(self.Ip)
        """_ExecuteScan_
        Método responsável por executar o método correspondente a cada protocolo escolhido pelo usuário para realizar uma varredura no target
        """

        try:
            if "icmp" in typeScan:
                scanner = pingScan.ScanIcmp
            elif "arp" in typeScan:
                scanner = pingScan.ScanArp
            elif "tcp" in typeScan:
                scanner = pingScan.ScanTcp
                pingScan.IpList = [(ip, porta)
                                   for ip in pingScan.IpList for porta in pingScan._DEFAULT_PORT]
            else:
                raise ValueError("Tipo de scan não suportado.")

            with ThreadPoolExecutor(max_workers=self.Threads) as executor:
                executor.map(scanner, pingScan.IpList)
        except Exception as e:
            logging.error(f"Erro durante a execução do scan: {e}")
