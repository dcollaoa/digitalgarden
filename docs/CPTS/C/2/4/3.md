Después de fuzzing un parámetro funcional, ahora debemos fuzzing el valor correcto que devolvería el contenido del `flag` que necesitamos. Esta sección discutirá fuzzing para valores de parámetros, lo cual debería ser bastante similar a fuzzing para parámetros, una vez que desarrollemos nuestra wordlist.

---

## Custom Wordlist

Cuando se trata de fuzzing valores de parámetros, es posible que no siempre encontremos una wordlist predefinida que funcione para nosotros, ya que cada parámetro esperaría un cierto tipo de valor.

Para algunos parámetros, como usernames, podemos encontrar una wordlist predefinida para posibles usernames, o podemos crear la nuestra basada en los usuarios que podrían estar usando el sitio web. Para estos casos, podemos buscar varias wordlists en el directorio `seclists` e intentar encontrar una que pueda contener valores que coincidan con el parámetro que estamos buscando. En otros casos, como parámetros personalizados, es posible que tengamos que desarrollar nuestra propia wordlist. En este caso, podemos suponer que el parámetro `id` puede aceptar una entrada numérica de algún tipo. Estos ids pueden estar en un formato personalizado, o pueden ser secuenciales, como de 1-1000 o 1-1000000, y así sucesivamente. Comenzaremos con una wordlist que contenga todos los números del 1 al 1000.

Hay muchas maneras de crear esta wordlist, desde escribir manualmente los IDs en un archivo, hasta hacerlo mediante scripting usando Bash o Python. La forma más simple es usar el siguiente comando en Bash que escribe todos los números del 1 al 1000 en un archivo:

```r
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

Una vez que ejecutemos nuestro comando, deberíamos tener nuestra wordlist lista:

```r
cat ids.txt

1
2
3
4
5
6
<...SNIP...>
```

Ahora podemos pasar a fuzzing para valores.

---

## Value Fuzzing

Nuestro comando debería ser bastante similar al comando `POST` que usamos para fuzzing de parámetros, pero nuestra palabra clave `FUZZ` debería estar donde estaría el valor del parámetro, y usaremos la wordlist `ids.txt` que acabamos de crear, de la siguiente manera:

```r
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.0.2
________________________________________________

 :: Method           : POST
 :: URL              : http://admin.academy.htb:PORT/admin/admin.php
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : id=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: xxx
________________________________________________

<...SNIP...>                      [Status: xxx, Size: xxx, Words: xxx, Lines: xxx]
```

Vemos que obtenemos un resultado de inmediato. Finalmente, podemos enviar otra solicitud `POST` usando `curl`, como hicimos en la sección anterior, usar el valor `id` que acabamos de encontrar y recolectar el flag.