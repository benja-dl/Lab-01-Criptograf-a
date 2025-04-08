from scapy.all import *
import sys
import time

def enviar_paquetes(mensaje):
    for char in mensaje:
        pkt = IP(dst="8.8.8.8")/ICMP(type=8)/Raw(load=char.encode('utf-8'))
        send(pkt, verbose=False)
        print(f".\nSent 1 packets.")
        time.sleep(0.5)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: sudo python3 pingv4.py '<mensaje_cifrado>'")
        sys.exit(1)
    enviar_paquetes(sys.argv[1])
