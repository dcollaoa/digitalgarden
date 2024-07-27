Ser capaz de comprender el concepto de `pivoting` lo suficientemente bien como para tener éxito en un engagement requiere una sólida comprensión fundamental de algunos conceptos clave de networking. Esta sección será un repaso rápido sobre conceptos fundamentales esenciales de networking para entender el pivoting.

## IP Addressing & NICs

Cada computadora que se comunica en una red necesita una dirección IP. Si no tiene una, no está en una red. La dirección IP se asigna en software y generalmente se obtiene automáticamente de un servidor DHCP. También es común ver computadoras con direcciones IP asignadas estáticamente. La asignación estática de IP es común en:

- Servers
- Routers
- Switch virtual interfaces
- Printers
- Y cualquier dispositivo que proporcione servicios críticos a la red

Ya sea asignada `dinámicamente` o `estáticamente`, la dirección IP se asigna a un `Network Interface Controller` (`NIC`). Comúnmente, el NIC se refiere como `Network Interface Card` o `Network Adapter`. Una computadora puede tener múltiples NICs (físicos y virtuales), lo que significa que puede tener múltiples direcciones IP asignadas, permitiéndole comunicarse en varias redes. Identificar oportunidades de pivoting a menudo dependerá de las IPs específicas asignadas a los hosts que comprometemos porque pueden indicar las redes que los hosts comprometidos pueden alcanzar. Por eso es importante que siempre verifiquemos la presencia de NICs adicionales utilizando comandos como `ifconfig` (en macOS y Linux) y `ipconfig` (en Windows).

### Using ifconfig

```r
ifconfig

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 134.122.100.200  netmask 255.255.240.0  broadcast 134.122.111.255
        inet6 fe80::e973:b08d:7bdf:dc67  prefixlen 64  scopeid 0x20<link>
        ether 12:ed:13:35:68:f5  txqueuelen 1000  (Ethernet)
        RX packets 8844  bytes 803773 (784.9 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5698  bytes 9713896 (9.2 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.106.0.172  netmask 255.255.240.0  broadcast 10.106.15.255
        inet6 fe80::a5bf:1cd4:9bca:b3ae  prefixlen 64  scopeid 0x20<link>
        ether 4e:c7:60:b0:01:8d  txqueuelen 1000  (Ethernet)
        RX packets 15  bytes 1620 (1.5 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 18  bytes 1858 (1.8 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 19787  bytes 10346966 (9.8 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 19787  bytes 10346966 (9.8 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.15.54  netmask 255.255.254.0  destination 10.10.15.54
        inet6 fe80::c85a:5717:5e3a:38de  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef:2::1034  prefixlen 64  scopeid 0x0<global>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 7  bytes 336 (336.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

En la salida anterior, cada NIC tiene un identificador (`eth0`, `eth1`, `lo`, `tun0`) seguido de información de direccionamiento y estadísticas de tráfico. La interfaz de túnel (tun0) indica que una conexión VPN está activa. Cuando nos conectamos a cualquiera de los servidores VPN de HTB a través de Pwnbox o nuestro propio host de ataque, siempre notaremos que se crea una interfaz de túnel y se le asigna una dirección IP. La VPN nos permite acceder a los entornos de red de laboratorio alojados por HTB. Ten en cuenta que estas redes de laboratorio no son accesibles sin tener un túnel establecido. La VPN encripta el tráfico y también establece un túnel a través de una red pública (a menudo Internet), a través de `NAT` en un dispositivo de red orientado al público y en la red interna/privada. Además, observa las direcciones IP asignadas a cada NIC. La IP asignada a eth0 (`134.122.100.200`) es una dirección IP públicamente enrutable. Esto significa que los ISP enrutarán el tráfico originado desde esta IP a través de Internet. Veremos IPs públicas en dispositivos que están directamente orientados a Internet, comúnmente alojados en DMZs. Las otras NICs tienen direcciones IP privadas, que son enrutable dentro de redes internas pero no a través de Internet pública. Al momento de escribir esto, cualquier persona que desee comunicarse a través de Internet debe tener al menos una dirección IP pública asignada a una interfaz en el dispositivo de red que se conecta a la infraestructura física conectada a Internet. Recuerda que NAT se usa comúnmente para traducir direcciones IP privadas a direcciones IP públicas.

### Using ipconfig

```r
PS C:\Users\htb-student> ipconfig

Windows IP Configuration

Unknown adapter NordLynx:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : .htb
   IPv6 Address. . . . . . . . . . . : dead:beef::1a9
   IPv6 Address. . . . . . . . . . . : dead:beef::f58b:6381:c648:1fb0
   Temporary IPv6 Address. . . . . . : dead:beef::dd0b:7cda:7118:3373
   Link-local IPv6 Address . . . . . : fe80::f58b:6381:c648:1fb0%8
   IPv4 Address. . . . . . . . . . . : 10.129.221.36
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:df81%8
                                       10.129.0.1

Ethernet adapter Ethernet:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
```

La salida directamente anterior es de emitir `ipconfig` en un sistema Windows. Podemos ver que este sistema tiene múltiples adaptadores, pero solo uno de ellos tiene direcciones IP asignadas. Hay direcciones [IPv6](https://www.cisco.com/c/en/us/solutions/ipv6/overview.html) y una dirección [IPv4](https://en.wikipedia.org/wiki/IPv4). Este módulo se centrará principalmente en redes que ejecutan IPv4, ya que sigue siendo el mecanismo de direccionamiento IP más común en LANs empresariales. Notaremos que algunos adaptadores, como el que se muestra en la salida anterior, tendrán una dirección IPv4 y una IPv6 asignadas en una [dual-stack configuration](https://www.cisco.com/c/dam/en_us/solutions/industries/docs/gov/IPV6at_a_glance_c45-625859.pdf), lo que permite que los recursos sean alcanzados a través de IPv4 o IPv6.

Cada dirección IPv4 tendrá una correspondiente `subnet mask`. Si una dirección IP es como un número de teléfono, la subnet mask es como el código de área. Recuerda que la subnet mask define la porción de

 `network` y `host` de una dirección IP. Cuando el tráfico de red está destinado a una dirección IP ubicada en una red diferente, la computadora enviará el tráfico a su `default gateway` asignado. El default gateway es generalmente la dirección IP asignada a un NIC en un dispositivo que actúa como el router para una LAN determinada. En el contexto de pivoting, necesitamos ser conscientes de qué redes puede alcanzar un host en el que aterrizamos, por lo que documentar tanta información de direccionamiento IP como sea posible en un engagement puede resultar útil.

---

## Routing

Es común pensar en un dispositivo de red que nos conecta a Internet cuando pensamos en un router, pero técnicamente cualquier computadora puede convertirse en un router y participar en el enrutamiento. Algunos de los desafíos que enfrentaremos en este módulo requieren que hagamos que un pivot host enrute tráfico a otra red. Una forma en que veremos esto es mediante el uso de AutoRoute, que permite que nuestra caja de ataque tenga `routes` a redes objetivo que son accesibles a través de un pivot host. Una característica clave definitoria de un router es que tiene una tabla de enrutamiento que utiliza para reenviar tráfico basado en la dirección IP de destino. Veamos esto en Pwnbox usando los comandos `netstat -r` o `ip route`.

### Routing Table on Pwnbox

```r
netstat -r

Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
default         178.62.64.1     0.0.0.0         UG        0 0          0 eth0
10.10.10.0      10.10.14.1      255.255.254.0   UG        0 0          0 tun0
10.10.14.0      0.0.0.0         255.255.254.0   U         0 0          0 tun0
10.106.0.0      0.0.0.0         255.255.240.0   U         0 0          0 eth1
10.129.0.0      10.10.14.1      255.255.0.0     UG        0 0          0 tun0
178.62.64.0     0.0.0.0         255.255.192.0   U         0 0          0 eth0
```

Notaremos que Pwnbox, distros de Linux, Windows y muchos otros sistemas operativos tienen una tabla de enrutamiento para ayudar al sistema a tomar decisiones de enrutamiento. Cuando se crea un paquete y tiene un destino antes de salir de la computadora, se usa la tabla de enrutamiento para decidir dónde enviarlo. Por ejemplo, si estamos tratando de conectar a un objetivo con la IP `10.129.10.25`, podríamos saber de la tabla de enrutamiento a dónde se enviaría el paquete para llegar allí. Se reenviaría a un `Gateway` a través del NIC correspondiente (`Iface`). Pwnbox no está usando ningún protocolo de enrutamiento (EIGRP, OSPF, BGP, etc...) para aprender cada una de esas rutas. Aprendió sobre esas rutas a través de sus propias interfaces directamente conectadas (eth0, eth1, tun0). Los dispositivos autónomos designados como routers generalmente aprenderán rutas utilizando una combinación de creación de rutas estáticas, protocolos de enrutamiento dinámico e interfaces directamente conectadas. Cualquier tráfico destinado a redes no presentes en la tabla de enrutamiento se enviará a la `default route`, que también puede referirse como el default gateway o gateway of last resort. Cuando busquemos oportunidades de pivot, puede ser útil mirar la tabla de enrutamiento de los hosts para identificar qué redes podemos alcanzar o qué rutas necesitamos agregar.

---

## Protocols, Services & Ports

`Protocols` son las reglas que gobiernan las comunicaciones de red. Muchos protocolos y servicios tienen correspondientes `ports` que actúan como identificadores. Los puertos lógicos no son cosas físicas que podamos tocar o conectar nada. Están en software asignados a aplicaciones. Cuando vemos una dirección IP, sabemos que identifica una computadora que puede ser alcanzada a través de una red. Cuando vemos un puerto abierto asignado a esa dirección IP, sabemos que identifica una aplicación a la que podemos conectar. Conectar a puertos específicos en los que un dispositivo está `listening` a menudo nos permite usar puertos y protocolos que son `permitted` en el firewall para obtener un foothold en la red.

Tomemos, por ejemplo, un servidor web usando HTTP (`a menudo escuchando en el puerto 80`). Los administradores no deberían bloquear el tráfico entrante en el puerto 80. Esto evitaría que cualquiera visite el sitio web que están alojando. Esta es a menudo una forma de entrar al entorno de red, `a través del mismo puerto por el que pasa el tráfico legítimo`. No debemos pasar por alto el hecho de que también se genera un `source port` para rastrear conexiones establecidas en el lado del cliente de una conexión. Debemos ser conscientes de qué puertos estamos usando para asegurarnos de que cuando ejecutemos nuestros payloads, se conecten a los listeners previstos que configuramos. Nos pondremos creativos con el uso de puertos a lo largo de este módulo.

Para una revisión adicional de los conceptos fundamentales de networking, por favor consulta el módulo [Introduction to Networking](https://academy.hackthebox.com/course/preview/introduction-to-networking).

---

Un consejo de LTNB0B: En este módulo, practicaremos muchas herramientas y técnicas diferentes para pivotar a través de hosts y reenviar servicios locales o remotos a nuestro host de ataque para acceder a objetivos conectados a diferentes redes. Este módulo aumenta gradualmente en dificultad, proporcionando redes de múltiples hosts para practicar lo aprendido. Te animo encarecidamente a que practiques muchos métodos diferentes de manera creativa a medida que comienzas a entender los conceptos. Tal vez incluso intentes dibujar las topologías de red utilizando herramientas de diagramación de red mientras enfrentas desafíos. Cuando busco oportunidades para pivotar, me gusta usar herramientas como [Draw.io](https://draw.io/) para construir una visualización del entorno de red en el que me encuentro, también sirve como una excelente herramienta de documentación. Este módulo es muy divertido y pondrá a prueba tus habilidades de networking. ¡Diviértete y nunca dejes de aprender!