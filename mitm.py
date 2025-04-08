from scapy.all import *
from termcolor import colored
import sys

def descifrar_cesar(texto, desplazamiento):
    mensaje = []
    for c in texto:
        if c == ' ':
            mensaje.append(' ')
            continue
        if not c.isalpha():
            mensaje.append(c)
            continue
        es_mayuscula = c.isupper()
        codigo = ord(c.lower())
        nuevo_codigo = (codigo - 97 - desplazamiento) % 26 + 97
        nuevo_caracter = chr(nuevo_codigo).upper() if es_mayuscula else chr(nuevo_codigo)
        mensaje.append(nuevo_caracter)
    return ''.join(mensaje)

def es_mensaje_probable(texto):
    palabras_comunes = {'y', 'en', 'un', 'es', 'de', 'con', 'hola', 'como'}
    texto_limpio = texto.lower().split()
    return sum(1 for palabra in texto_limpio if palabra in palabras_comunes) >= 2

def leer_pcapng(archivo):
    mensaje = []
    paquetes = rdpcap(archivo)
    for pkt in paquetes:
        if (
            pkt.haslayer(ICMP) and 
            pkt[ICMP].type == 8 and 
            pkt.haslayer(Raw) and 
            pkt[IP].dst == "8.8.8.8"
        ):
            try:
                char = pkt[Raw].load.decode('utf-8', errors='ignore')
                mensaje.append(char)
            except:
                pass
    return ''.join(mensaje)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: sudo python3 mitm.py <ruta_archivo.pcapng>")
        sys.exit(1)
    
    archivo_pcap = sys.argv[1]
    mensaje_cifrado = leer_pcapng(archivo_pcap)
    print(f"\nMensaje cifrado capturado: {mensaje_cifrado}")
    
    combinaciones = [(d, descifrar_cesar(mensaje_cifrado, d)) for d in range(26)]
    mejor_opcion = max(combinaciones, key=lambda x: es_mensaje_probable(x[1]))
    
    print("\nResultados para todos los desplazamientos:")
    for d, texto in combinaciones:
        if (d, texto) == mejor_opcion:
            print(colored(f"{d:2d}: {texto}", 'blue')) 
        else:
            print(f"{d:2d}: {texto}")
