import IpDetect.PingScan as PingScan
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

if __name__ == "__main__":
    # typeScan = sys.argv[1]
    ip_scanner = PingScan.PingScan("inventsoftware.com.br")
    ip_scanner.ExecuteScan("tcp")
