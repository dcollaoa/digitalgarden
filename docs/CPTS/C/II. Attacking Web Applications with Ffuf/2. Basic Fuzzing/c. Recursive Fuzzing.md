Hasta ahora, hemos estado fuzzing para directorios, luego entrando en estos directorios y fuzzing para archivos. Sin embargo, si tuviéramos docenas de directorios, cada uno con sus propios subdirectorios y archivos, esto tomaría mucho tiempo para completar. Para poder automatizar esto, utilizaremos lo que se conoce como `recursive fuzzing`.

---

## Recursive Flags

Cuando escaneamos de forma recursiva, automáticamente comienza otro escaneo bajo cualquier directorio nuevo identificado que pueda tener en sus páginas hasta que haya fuzzed el sitio web principal y todos sus subdirectorios.

Algunos sitios web pueden tener un gran árbol de subdirectorios, como `/login/user/content/uploads/...etc`, y esto expandirá el árbol de escaneo y puede tomar mucho tiempo escanearlos todos. Por eso, siempre se aconseja especificar una `depth` a nuestro escaneo recursivo, de modo que no escanee directorios que sean más profundos que esa profundidad. Una vez que fuzzemos los primeros directorios, podemos seleccionar los directorios más interesantes y ejecutar otro escaneo para dirigir mejor nuestro escaneo.

En `ffuf`, podemos habilitar el escaneo recursivo con la flag `-recursion`, y podemos especificar la profundidad con la flag `-recursion-depth`. Si especificamos `-recursion-depth 1`, solo fuzzeará los directorios principales y sus subdirectorios directos. Si se identifican sub-sub-directorios (como `/login/user`), no los fuzzeará para páginas. Al usar la recursión en `ffuf`, podemos especificar nuestra extensión con `-e .php`.

Nota: aún podemos usar `.php` como nuestra extensión de página, ya que estas extensiones suelen ser de todo el sitio.

Finalmente, también añadiremos la flag `-v` para mostrar las URLs completas. De lo contrario, puede ser difícil saber qué archivo `.php` está bajo qué directorio.

---

## Recursive Scanning

Repitamos el primer comando que usamos, añadamos las flags de recursión mientras especificamos `.php` como nuestra extensión, y veamos qué resultados obtenemos:

```r
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://SERVER_IP:PORT/FUZZ
 :: Wordlist         : FUZZ: /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

[Status: 200, Size: 986, Words: 423, Lines: 56] | URL | http://SERVER_IP:PORT/
    * FUZZ: 

[INFO] Adding a new job to the queue: http://SERVER_IP:PORT/forum/FUZZ
[Status: 200, Size: 986, Words: 423, Lines: 56] | URL | http://SERVER_IP:PORT/index.php
    * FUZZ: index.php

[Status: 301, Size: 326, Words: 20, Lines: 10] | URL | http://SERVER_IP:PORT/blog | --> | http://SERVER_IP:PORT/blog/
    * FUZZ: blog

<...SNIP...>
[Status: 200, Size: 0, Words: 1, Lines: 1] | URL | http://SERVER_IP:PORT/blog/index.php
    * FUZZ: index.php

[Status: 200, Size: 0, Words: 1, Lines: 1] | URL | http://SERVER_IP:PORT/blog/
    * FUZZ: 

<...SNIP...>
```

Como podemos ver esta vez, el escaneo tomó mucho más tiempo, envió casi seis veces la cantidad de solicitudes y la lista de palabras se duplicó en tamaño (una vez con `.php` y otra sin). Aún así, obtuvimos una gran cantidad de resultados, incluidos todos los resultados que identificamos anteriormente, todo con una sola línea de comando.