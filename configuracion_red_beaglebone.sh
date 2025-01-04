#!/bin/bash

#script para efectuar la configuracion no persistente de la red cada vez que se enciende la beagle

#configurar el gateway de ipv4 y el dns
sudo route add default gw 192.168.6.1
sudo systemd-resolve --set-dns=8.8.8.8 --interface=usb1

#configurar la direccion ip (global)
sudo ip addr add b:b:b::/64 dev usb1

#configurar usb1 como ruta por defecto para ipv6
sudo ip route add ::/0 dev usb1

#asegurar que no se comporta como router ipv6 (no deberia ser necesario)
sudo sysctl -w net.ipv6.conf.all.forwarding=0
