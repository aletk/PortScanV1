import socket
import re


class GerarListIps():
    """_GerarListIps_
    Classe responsável por retornar e tratar o ip passado pelo usuário
    Returns:
        [ip,ip]
    """

    IPRANGE: str = "0/24"

    def __init__(self, ipRange: str):
        self.IpParaConsulta: str = ipRange
        self.IpList: [str] = self.ObterListaDeIp()

    def ObterListaDeIp(self) -> [str]:
        """_ObterListaDeIp_
        Alimenta a lista de ips que irão ser consultados durante o scan na rede 
        """
        if self.ValidateIpOrName():
            self.DnsResolver()

        loadRange: str = self.IpParaConsulta.split(".")[3]
        cutIp: str = '.'.join(self.IpParaConsulta.split(".")[0:3])

        if loadRange.__contains__(self.IPRANGE):
            return [f"{cutIp}.{rangeIp}" for rangeIp in range(255)]

        return [self.IpParaConsulta]

    def ValidateIpOrName(self) -> bool:
        """_ValidateIpOrName_
        Validação se é Ip ou nome informado pelo usuario para realizar a resolução de dns se necessario
        """
        return bool(re.search(r"[a-zA-Z]", self.IpParaConsulta))

    def DnsResolver(self) -> None:
        """_DnsResolver_
        Realiza uma busca no DNS do dominio informado e retorna o endereço encontrado
        """
        self.IpParaConsulta = socket.gethostbyname(self.IpParaConsulta)

    def ListaDeIp(self):
        """_ListDeIp_
        Retorna a lista de ips que serão informadas pelo usuário
        """
        return self.IpList
