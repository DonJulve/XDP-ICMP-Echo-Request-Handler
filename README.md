# XDP ICMP Echo Request Handler
Este programa utiliza XDP (eBPF) para interceptar y modificar paquetes de red ICMP y ICMPv6. Su objetivo es interceptar solicitudes de eco ICMP (ping) y ICMPv6, intercambiando las direcciones de origen y destino, y modificando el tipo del mensaje a la respuesta de eco correspondiente.

## Funcionalidad
- **Intercambio de direcciones MAC**: Cambia las direcciones MAC de origen y destino en los paquetes Ethernet.
- **ICMP sobre IPv4**: Si el paquete es una solicitud de eco ICMP (Echo Request), intercambia las direcciones IP de origen y destino, cambia el tipo a Echo Reply y actualiza el checksum del paquete.
- **ICMP sobre IPv6**: Si el paquete es una solicitud de eco ICMPv6 (Echo Request), intercambia las direcciones IP de origen y destino, cambia el tipo a Echo Reply y actualiza el checksum del paquete.

## ¿Cómo funciona?
1. **XDP**: El programa se carga y ejecuta en el contexto de un XDP program, que es un tipo de programa eBPF que se ejecuta en la capa más baja de la pila de red, directamente en la interfaz de red.

2. **Procesamiento de paquetes**:
- Cuando un paquete ICMPv4 o ICMPv6 llega a la interfaz de red, el programa:
    1. Verifica si el paquete es ICMPv4 o ICMPv6.
    2. Si es una solicitud de eco (Echo Request), intercambia las direcciones de origen y destino.
    3. Modifica el tipo de ICMP a Echo Reply (respuesta de eco).
    4. Actualiza el checksum de ICMP (tanto para IPv4 como para IPv6) para reflejar el cambio de tipo de mensaje.

3. **Respuesta al paquete**: El programa luego reenvía el paquete con los cambios realizados.

## Requisitos
- **Kernel**: 4.8 o superior.
- **Herramientas**: `clang`, `xdp`.

## Dependencias
```bash
sudo apt install clang llvm libelf-dev libbpf-dev libpcap-dev build-essential
sudo apt install linux-headers-$(uname -r)
```

Debian:
```bash
sudo apt install linux-perf
```

Ubuntu:
```bash
sudo apt install linux-tools-$(uname -r)
```

## Problemas
/usr/include/linux/types.h:5:10: fatal error: 'asm/types.h' file not found **

Encuentra donde está el archivo .h, podría no estar en /usr/include

```bash
find /usr/include/ -name types.h | grep asm
```
Haz un softlink entre los headers y donde la librería espera que estén:
```bash
sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
```
Este problema puede ocurrir con otros headers requeridos dependiendo de la distribución de linux. Las soluciones proporcionadas arriba funcionan con cualquier otro header.

## Uso
1. **Compilación**:
```bash
clang -O2 -target bpf -c echo_server.c -o echo_server.o
```

2. **Carga del programa**:
```bash
sudo ip link set dev <interface> xdp obj echo_server.o sec xdp
```

3. **Descarga del programa**:
```bash
sudo ip link set dev <interface> xdp off
```


