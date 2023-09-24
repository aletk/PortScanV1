from ipwhois import IPWhois
from IpDetect.IpGenerator import IpGenerator
import re
import socket


class ConsultaRdap(IpGenerator):

    def __init__(self, ip) -> None:
        super().__init__(ip)

    def ConsultRdap(self) -> None:
        for ip in self.IpList:
            connectRdap = IPWhois(ip)
            resultRdap = connectRdap.lookup_rdap()
            self.HandleConsultRdap(resultRdap)

    def HandleConsultRdap(self, returnRdap: dict):
        """
        Manipula os resultados da consulta RDAP e imprime as informações.

        Args:
            returnRdap (dict): Dados da consulta RDAP.
        """
        ip = returnRdap.get('query', 'N/A')
        network_handle = returnRdap['network'].get('handle', 'N/A')
        entities = ', '.join(returnRdap.get('entities', ['N/A']))
        asn_description = returnRdap.get('asn_description', 'N/A')

        rdapConstruct = (
            f"[+] IP Consultado: {ip}\n"
            f"[+] Bloco De Ip: {network_handle}\n"
            f"[+] Entidades: {entities}\n"
            f"[+] Descrição: {asn_description}"
        )
        print(rdapConstruct)
