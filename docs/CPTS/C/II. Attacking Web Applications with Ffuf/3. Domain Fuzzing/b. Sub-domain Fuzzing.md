En esta sección, aprenderemos cómo usar `ffuf` para identificar sub-dominios (es decir, `*.website.com`) para cualquier sitio web.

---

## Sub-domains

Un sub-domino es cualquier sitio web que subyace a otro dominio. Por ejemplo, `https://photos.google.com` es el sub-dominio `photos` de `google.com`.

En este caso, simplemente estamos verificando diferentes sitios web para ver si existen comprobando si tienen un registro DNS público que nos redirija a una IP de servidor funcional. Así que, vamos a ejecutar un escaneo y ver si obtenemos algún resultado. Antes de poder comenzar nuestro escaneo, necesitamos dos cosas:

- Una `wordlist`
- Un `target`

Afortunadamente para nosotros, en el repositorio `SecLists`, hay una sección específica para wordlists de sub-dominios, que consiste en palabras comunes usualmente usadas para sub-dominios. Podemos encontrarla en `/opt/useful/SecLists/Discovery/DNS/`. En nuestro caso, usaremos una wordlist más corta, que es `subdomains-top1million-5000.txt`. Si queremos extender nuestro escaneo, podemos elegir una lista más grande.

En cuanto a nuestro target, usaremos `inlanefreight.com` como nuestro objetivo y ejecutaremos nuestro escaneo sobre él. Usemos `ffuf` y coloquemos la palabra clave `FUZZ` en lugar de los sub-dominios, y veamos si obtenemos algún resultado:

```r
ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : https://FUZZ.inlanefreight.com/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 381ms]
    * FUZZ: support

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 385ms]
    * FUZZ: ns3

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 402ms]
    * FUZZ: blog

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 180ms]
    * FUZZ: my

[Status: 200, Size: 22266, Words: 2903, Lines: 316, Duration: 589ms]
    * FUZZ: www

<...SNIP...>
```

Vemos que obtenemos algunos resultados. Ahora, podemos intentar ejecutar lo mismo en `academy.htb` y ver si obtenemos algún resultado:

```r
ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.academy.htb/


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : https://FUZZ.academy.htb/
 :: Wordlist         : FUZZ: /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

:: Progress: [4997/4997] :: Job [1/1] :: 131 req/sec :: Duration: [0:00:38] :: Errors: 4997 ::
```

Vemos que no obtenemos ningún resultado. ¿Significa esto que no hay sub-dominios bajo `academy.htb`? - No.

Esto significa que no hay sub-dominios `public` bajo `academy.htb`, ya que no tiene un registro DNS público, como se mencionó anteriormente. Aunque agregamos `academy.htb` a nuestro archivo `/etc/hosts`, solo agregamos el dominio principal, por lo que cuando `ffuf` busca otros sub-dominios, no los encontrará en `/etc/hosts`, y preguntará al DNS público, que obviamente no los tendrá.