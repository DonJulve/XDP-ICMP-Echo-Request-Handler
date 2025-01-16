#!/bin/bash

# Solicitar las interfaces de entrada y salida
read -p "Introduce la interfaz de la beaglebone: " INTERFACE_IN
read -p "Introduce la interfaz de red del pc: " INTERFACE_OUT

# Activar el reenvío de paquetes IPv4
sudo sysctl -w net.ipv4.ip_forward=1

# Configurar reglas de iptables
sudo iptables -A FORWARD -i "$INTERFACE_IN" -o "$INTERFACE_OUT" -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i "$INTERFACE_OUT" -o "$INTERFACE_IN" -j ACCEPT
sudo iptables -t nat -A POSTROUTING -o "$INTERFACE_OUT" -j MASQUERADE

#configurar la direccion ipv6 
sudo ip addr add c:a:f:e::/64 dev "$INTERFACE_IN"

#configurar la interfaz correspondiente al puerto conectado a la beagle como ruta por defecto para ipv6
sudo ip route add ::/0 dev "$INTERFACE_IN"

#asegurar que no se comporta como router ipv6 (no deberia ser necesario)
sudo sysctl -w net.ipv6.conf.all.forwarding=0