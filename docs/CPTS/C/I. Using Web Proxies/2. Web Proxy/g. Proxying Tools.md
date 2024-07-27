Un aspecto importante del uso de proxies web es habilitar la intercepción de solicitudes web realizadas por herramientas de línea de comandos y aplicaciones cliente pesado. Esto nos proporciona transparencia en las solicitudes web realizadas por estas aplicaciones y nos permite utilizar todas las diferentes funciones de proxy que hemos utilizado con aplicaciones web.

Para enrutar todas las solicitudes web realizadas por una herramienta específica a través de nuestras herramientas de proxy web, debemos configurarlas como el proxy de la herramienta (es decir, `http://127.0.0.1:8080`), de manera similar a lo que hicimos con nuestros navegadores. Cada herramienta puede tener un método diferente para configurar su proxy, por lo que es posible que tengamos que investigar cómo hacerlo para cada una.

Esta sección cubrirá algunos ejemplos de cómo usar proxies web para interceptar solicitudes web realizadas por dichas herramientas. Puedes usar Burp o ZAP, ya que el proceso de configuración es el mismo.

Nota: Proxying tools usualmente los ralentiza, por lo tanto, solo usa proxies cuando necesites investigar sus solicitudes y no para uso normal.

---

## Proxychains

Una herramienta muy útil en Linux es [proxychains](https://github.com/haad/proxychains), que enruta todo el tráfico proveniente de cualquier herramienta de línea de comandos a cualquier proxy que especifiquemos. `Proxychains` añade un proxy a cualquier herramienta de línea de comandos y, por lo tanto, es el método más simple y fácil para enrutar el tráfico web de herramientas de línea de comandos a través de nuestros proxies web.

Para usar `proxychains`, primero tenemos que editar `/etc/proxychains.conf`, comentar la última línea y añadir la siguiente línea al final:

```r
#socks4         127.0.0.1 9050
http 127.0.0.1 8080
```

También deberíamos habilitar `Quiet Mode` para reducir el ruido descomentando `quiet_mode`. Una vez hecho esto, podemos anteponer `proxychains` a cualquier comando, y el tráfico de ese comando debería ser enrutado a través de `proxychains` (es decir, nuestro proxy web). Por ejemplo, intentemos usar `cURL` en uno de nuestros ejercicios anteriores:

```r
proxychains curl http://SERVER_IP:PORT

ProxyChains-3.1 (http://proxychains.sf.net)
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Ping IP</title>
    <link rel="stylesheet" href="./style.css">
</head>
...SNIP...
</html>    
```

Vemos que funcionó como normalmente lo haría, con la línea adicional `ProxyChains-3.1` al principio, para notar que se está enroutando a través de `ProxyChains`. Si volvemos a nuestro proxy web (Burp en este caso), veremos que la solicitud efectivamente pasó por él:

![Proxychains Curl](https://academy.hackthebox.com/storage/modules/110/proxying_proxychains_curl.jpg)

---

## Nmap

A continuación, intentemos enrutar `nmap` a través de nuestro proxy web. Para saber cómo usar las configuraciones de proxy para cualquier herramienta, podemos ver su manual con `man nmap`, o su página de ayuda con `nmap -h`:

```r
nmap -h | grep -i prox

  --proxies <url1,[url2],...>: Relay connections through HTTP/SOCKS4 proxies
```

Como podemos ver, podemos usar la flag `--proxies`. También deberíamos añadir la flag `-Pn` para omitir el descubrimiento de hosts (como se recomienda en el manual). Finalmente, también usaremos la flag `-sC` para examinar lo que hace un escaneo de scripts de nmap:

```r
nmap --proxies http://127.0.0.1:8080 SERVER_IP -pPORT -Pn -sC

Starting Nmap 7.91 ( https://nmap.org )
Nmap scan report for SERVER_IP
Host is up (0.11s latency).

PORT      STATE SERVICE
PORT/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds
```

Una vez más, si vamos a nuestra herramienta de proxy web, veremos todas las solicitudes realizadas por nmap en el historial del proxy:

![nmap proxy](https://academy.hackthebox.com/storage/modules/110/proxying_nmap.jpg)

Nota: El proxy integrado de Nmap todavía está en su fase experimental, como se menciona en su manual (`man nmap`), por lo que no todas las funciones o el tráfico pueden ser enroutados a través del proxy. En estos casos, simplemente podemos recurrir a `proxychains`, como hicimos anteriormente.

---

## Metasploit

Finalmente, intentemos enrutar el tráfico web realizado por los módulos de Metasploit para investigarlos y depurarlos mejor. Deberíamos comenzar iniciando Metasploit con `msfconsole`. Luego, para configurar un proxy para cualquier exploit dentro de Metasploit, podemos usar la flag `set PROXIES`. Probemos el escáner `robots_txt` como ejemplo y ejecutémoslo contra uno de nuestros ejercicios anteriores:

```r
msfconsole

msf6 > use auxiliary/scanner/http/robots_txt
msf6 auxiliary(scanner/http/robots_txt) > set PROXIES HTTP:127.0.0.1:8080

PROXIES => HTTP:127.0.0.1:8080


msf6 auxiliary(scanner/http/robots_txt) > set RHOST SERVER_IP

RHOST => SERVER_IP


msf6 auxiliary(scanner/http/robots_txt) > set RPORT PORT

RPORT => PORT


msf6 auxiliary(scanner/http/robots_txt) > run

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Una vez más, podemos volver a nuestra herramienta de proxy web de elección y examinar el historial del proxy para ver todas las solicitudes enviadas:

![msf proxy](https://academy.hackthebox.com/storage/modules/110/proxying_msf.jpg)

Vemos que la solicitud efectivamente pasó por nuestro proxy web. El mismo método puede usarse con otros escáneres, exploits y otras características en Metasploit.

Podemos utilizar nuestros proxies web de manera similar con otras herramientas y aplicaciones, incluidos scripts y clientes pesados. Todo lo que tenemos que hacer es configurar el proxy de cada herramienta para usar nuestro proxy web. Esto nos permite examinar exactamente qué están enviando y recibiendo estas herramientas y potencialmente repetir y modificar sus solicitudes mientras realizamos pruebas de penetración en aplicaciones web.