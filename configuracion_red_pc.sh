#!/bin/bash

# Solicitar las interfaces de entrada y salida
read -p "Introduce la interfaz de entrada: " INTERFACE_IN
read -p "Introduce la interfaz de salida: " INTERFACE_OUT

# Activar el reenvío de paquetes IPv4
sudo sysctl -w net.ipv4.ip_forward=1

# Configurar reglas de iptables
sudo iptables -A FORWARD -i "$INTERFACE_IN" -o "$INTERFACE_OUT" -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i "$INTERFACE_OUT" -o "$INTERFACE_IN" -j ACCEPT
sudo iptables -t nat -A POSTROUTING -o "$INTERFACE_OUT" -j MASQUERADE

