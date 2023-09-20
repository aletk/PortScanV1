import IpDetect.PingScan as PingScan
import logging
from Controller.controller import Constroller
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

if __name__ == "__main__":
    # typeScan = sys.argv[1]
    ip_scanner = Constroller("tcp", "inventsoftware.com.br")
    ip_scanner.ExecuteConsult()
