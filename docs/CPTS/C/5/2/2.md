Podemos enfrentar muchos problemas al configurar SQLMap o usarlo con solicitudes HTTP. En esta sección, discutiremos los mecanismos recomendados para encontrar la causa y solucionarlos adecuadamente.

---

## Display Errors

El primer paso suele ser activar la opción `--parse-errors`, para analizar los errores del DBMS (si los hay) y mostrarlos como parte de la ejecución del programa:



```r
...SNIP...
[16:09:20] [INFO] testing if GET parameter 'id' is dynamic
[16:09:20] [INFO] GET parameter 'id' appears to be dynamic
[16:09:20] [WARNING] parsed DBMS error message: 'SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '))"',),)((' at line 1'"
[16:09:20] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')
[16:09:20] [WARNING] parsed DBMS error message: 'SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''YzDZJELylInm' at line 1'
...SNIP...
```

Con esta opción, SQLMap imprimirá automáticamente el error del DBMS, dándonos claridad sobre cuál puede ser el problema para poder solucionarlo adecuadamente.

---

## Store the Traffic

La opción `-t` almacena todo el contenido del tráfico en un archivo de salida:



```r
sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt

cat /tmp/traffic.txt
HTTP request [#1]:
GET /?id=1 HTTP/1.1
Host: www.example.com
Cache-control: no-cache
Accept-encoding: gzip,deflate
Accept: */*
User-agent: sqlmap/1.4.9 (http://sqlmap.org)
Connection: close

HTTP response [#1] (200 OK):
Date: Thu, 24 Sep 2020 14:12:50 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Encoding: gzip
Content-Length: 914
Connection: close
Content-Type: text/html; charset=UTF-8
URI: http://www.example.com:80/?id=1

<!DOCTYPE html>
<html lang="en">
...SNIP...
```

Como podemos ver en el resultado anterior, el archivo `/tmp/traffic.txt` ahora contiene todas las solicitudes y respuestas HTTP enviadas y recibidas. Así, podemos investigar manualmente estas solicitudes para ver dónde ocurre el problema.

---

## Verbose Output

Otra opción útil es la `-v`, que aumenta el nivel de verbosidad de la salida de la consola:



```r
sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.4.9}
|_ -| . [(]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org


[*] starting @ 16:17:40 /2020-09-24/

[16:17:40] [DEBUG] cleaning up configuration parameters
[16:17:40] [DEBUG] setting the HTTP timeout
[16:17:40] [DEBUG] setting the HTTP User-Agent header
[16:17:40] [DEBUG] creating HTTP requests opener object
[16:17:40] [DEBUG] resolving hostname 'www.example.com'
[16:17:40] [INFO] testing connection to the target URL
[16:17:40] [TRAFFIC OUT] HTTP request [#1]:
GET /?id=1 HTTP/1.1
Host: www.example.com
Cache-control: no-cache
Accept-encoding: gzip,deflate
Accept: */*
User-agent: sqlmap/1.4.9 (http://sqlmap.org)
Connection: close

[16:17:40] [DEBUG] declared web page charset 'utf-8'
[16:17:40] [TRAFFIC IN] HTTP response [#1] (200 OK):
Date: Thu, 24 Sep 2020 14:17:40 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Encoding: gzip
Content-Length: 914
Connection: close
Content-Type: text/html; charset=UTF-8
URI: http://www.example.com:80/?id=1

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <meta name="description" content="">
  <meta name="author" content="">
  <link href="vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
  <title>SQLMap Essentials - Case1</title>
</head>

<body>
...SNIP...
```

Como podemos ver, la opción `-v 6` imprimirá directamente todos los errores y la solicitud HTTP completa en la terminal para que podamos seguir todo lo que SQLMap está haciendo en tiempo real.

---

## Using Proxy

Finalmente, podemos utilizar la opción `--proxy` para redirigir todo el tráfico a través de un proxy (MiTM) (por ejemplo, `Burp`). Esto enruta todo el tráfico de SQLMap a través de `Burp`, para que luego podamos investigar manualmente todas las solicitudes, repetirlas y utilizar todas las funciones de `Burp` con estas solicitudes:

![burp_proxy](https://academy.hackthebox.com/storage/modules/58/eIwJeV3.png)