import IpDetect.PingScan as PingScan
import logging
from Controller.controller import Constroller
import argparse
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.basicConfig(level=logging.DEBUG)

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    
    parser.add_argument("--host", type=str, required=True,
                        help=" --host 192.168.0.0/24")
    parser.add_argument("--type", type=str, help="--type tcp", default="tcp")
    parser.add_argument("--threads", type=int, default=40,
                        help=" -t 10 ; numero de threads a ser passado")

    args = parser.parse_args()
    ip_scanner = Constroller(args.type, args.host, args.threads)

    ip_scanner.ExecuteConsult()
