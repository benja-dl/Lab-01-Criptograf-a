import sys 

def cifrar_cesar(texto, desplazamiento):
    resultado = []
    for caracter in texto:
        if caracter == ' ':
            resultado.append(' ')
            continue
        if not caracter.isalpha():
            resultado.append(caracter)
            continue
        es_mayuscula = caracter.isupper()
        codigo = ord(caracter.lower())
        nuevo_codigo = (codigo - 97 + desplazamiento) % 26 + 97
        nuevo_caracter = chr(nuevo_codigo).upper() if es_mayuscula else chr(nuevo_codigo)
        resultado.append(nuevo_caracter)
    return ''.join(resultado)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: sudo python3 cesar.py '<texto>' <desplazamiento>")
        sys.exit(1)
    texto = sys.argv[1]
    desplazamiento = int(sys.argv[2])
    print(cifrar_cesar(texto, desplazamiento))
