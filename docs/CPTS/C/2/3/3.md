Como vimos en la sección anterior, pudimos fuzzing sub-dominios públicos utilizando registros DNS públicos. Sin embargo, cuando se trata de fuzzing sub-dominios que no tienen un registro DNS público o sub-dominios bajo sitios web que no son públicos, no pudimos usar el mismo método. En esta sección, aprenderemos cómo hacer eso con `Vhost Fuzzing`.

---

## Vhosts vs. Sub-domains

La diferencia clave entre VHosts y sub-dominios es que un VHost es básicamente un 'sub-dominio' servido en el mismo servidor y tiene la misma IP, de modo que una sola IP podría estar sirviendo a dos o más sitios web diferentes.

`VHosts may or may not have public DNS records.`

En muchos casos, muchos sitios web tendrían sub-dominios que no son públicos y no los publicarán en registros DNS públicos, por lo que si los visitamos en un navegador, no podríamos conectarnos, ya que el DNS público no sabría su IP. Una vez más, si usamos el `sub-domain fuzzing`, solo podríamos identificar sub-dominios públicos, pero no identificaríamos ningún sub-dominio que no sea público.

Aquí es donde utilizamos `VHosts Fuzzing` en una IP que ya tenemos. Ejecutaremos un escaneo y probaremos para escaneos en la misma IP, y luego podremos identificar tanto sub-dominios públicos como no públicos y VHosts.

---

## Vhosts Fuzzing

Para escanear VHosts, sin agregar manualmente toda la wordlist a nuestro `/etc/hosts`, haremos fuzzing en los encabezados HTTP, específicamente el encabezado `Host:`. Para hacerlo, podemos usar la flag `-H` para especificar un encabezado y usaremos la palabra clave `FUZZ` dentro de él, de la siguiente manera:

```r
ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://academy.htb:PORT/
 :: Wordlist         : FUZZ: /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.academy.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

mail2                   [Status: 200, Size: 900, Words: 423, Lines: 56]
dns2                    [Status: 200, Size: 900, Words: 423, Lines: 56]
ns3                     [Status: 200, Size: 900, Words: 423, Lines: 56]
dns1                    [Status: 200, Size: 900, Words: 423, Lines: 56]
lists                   [Status: 200, Size: 900, Words: 423, Lines: 56]
webmail                 [Status: 200, Size: 900, Words: 423, Lines: 56]
static                  [Status: 200, Size: 900, Words: 423, Lines: 56]
web                     [Status: 200, Size: 900, Words: 423, Lines: 56]
www1                    [Status: 200, Size: 900, Words: 423, Lines: 56]
<...SNIP...>
```

¡Vemos que todas las palabras en la wordlist están devolviendo `200 OK`! Esto es de esperarse, ya que simplemente estamos cambiando el encabezado mientras visitamos `http://academy.htb:PORT/`. Así que, sabemos que siempre obtendremos `200 OK`. Sin embargo, si el VHost existe y enviamos uno correcto en el encabezado, deberíamos obtener un tamaño de respuesta diferente, ya que en ese caso, obtendríamos la página de ese VHost, que probablemente mostraría una página diferente.