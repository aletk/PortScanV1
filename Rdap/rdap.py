from ipwhois import IPWhois
from IpDetect.GerarListIps import GerarListIps
import re
import socket


class ConsultaRdap(GerarListIps):

    def __init__(self, ip):
        super().__init__(ip)

    def ConsultarRdap(self):
        for ip in self.IpList:
            connectRdap = IPWhois()
        resultRdap = connectRdap.lookup_rdap()
        print(resultRdap)
