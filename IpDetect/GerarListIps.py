import socket
import re


"""_GerarListIps_
Classe responsável por retornar e tratar o ip passado pelo usuário
    Returns:
        [ip,ip]
"""


class GerarListIps():

    IPRANGE: str = "0/24"

    def __init__(self, ipRange: str):
        self.IpParaConsulta: str = ipRange
        self.IpList: [str] = self.ObterListaDeIp()

    """_ObterListaDeIp_
    Alimenta a lista de ips que irão ser consultados durante o scan na rede 
    """

    def ObterListaDeIp(self) -> [str]:
        if self.ValidateIpOrName():
            self.DnsResolver()

        loadRange: str = self.IpParaConsulta.split(".")[3]
        cutIp: str = '.'.join(self.IpParaConsulta.split(".")[0:3])

        if loadRange.__contains__(self.IPRANGE):
            return [f"{cutIp}.{rangeIp}" for rangeIp in range(255)]

        return [self.IpParaConsulta]

    """_ValidateIpOrName_
    Validação se é Ip ou nome informado pelo usuario para realizar a resolução de dns se necessario
    """

    def ValidateIpOrName(self) -> bool:
        return bool(re.search(r"[a-zA-Z]", self.IpParaConsulta))

    """_DnsResolver_
    Realiza uma busca no DNS do dominio informado e retorna o endereço encontrado
    """

    def DnsResolver(self) -> None:
        self.IpParaConsulta = socket.gethostbyname(self.IpParaConsulta)

    """_ListDeIp_
    Retorna a lista de ips que serão informadas pelo usuário
    """

    def ListaDeIp(self):
        return self.IpList
