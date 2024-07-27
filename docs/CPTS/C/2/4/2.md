La principal diferencia entre las solicitudes `POST` y las solicitudes `GET` es que las solicitudes `POST` no se pasan con la URL y no se pueden simplemente agregar después de un símbolo `?`. Las solicitudes `POST` se pasan en el campo `data` dentro de la solicitud HTTP. Consulta el módulo [Web Requests](https://academy.hackthebox.com/module/details/35) para aprender más sobre solicitudes HTTP.

Para fuzzing el campo `data` con `ffuf`, podemos usar la flag `-d`, como vimos anteriormente en la salida de `ffuf -h`. También debemos agregar `-X POST` para enviar solicitudes `POST`.

Consejo: En PHP, los datos "POST" solo pueden aceptar el "content-type" "application/x-www-form-urlencoded". Por lo tanto, podemos establecer eso en "ffuf" con "-H 'Content-Type: application/x-www-form-urlencoded'".

Entonces, repitamos lo que hicimos antes, pero coloquemos nuestra palabra clave `FUZZ` después de la flag `-d`:

```r
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : POST
 :: URL              : http://admin.academy.htb:PORT/admin/admin.php
 :: Wordlist         : FUZZ: /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : FUZZ=key
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: xxx
________________________________________________

id                      [Status: xxx, Size: xxx, Words: xxx, Lines: xxx]
<...SNIP...>
```

Como podemos ver esta vez, obtuvimos un par de resultados, el mismo que obtuvimos cuando fuzzing `GET` y otro parámetro, que es `id`. Veamos qué obtenemos si enviamos una solicitud `POST` con el parámetro `id`. Podemos hacerlo con `curl`, de la siguiente manera:

```r
curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'

<div class='center'><p>Invalid id!</p></div>
<...SNIP...>
```

Como podemos ver, el mensaje ahora dice `Invalid id!`.