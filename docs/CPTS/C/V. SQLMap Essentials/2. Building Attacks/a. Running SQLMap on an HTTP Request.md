
## Curl Commands

Una de las mejores y más fáciles maneras de configurar correctamente una solicitud de SQLMap contra un objetivo específico (es decir, una solicitud web con parámetros dentro) es utilizando la función `Copy as cURL` desde el panel de Network (Monitor) en las herramientas para desarrolladores de Chrome, Edge o Firefox: ![copy_as_curl](https://academy.hackthebox.com/storage/modules/58/M5UVR6n.png)

Pegando el contenido del portapapeles (`Ctrl-V`) en la línea de comandos y cambiando el comando original `curl` por `sqlmap`, podemos usar SQLMap con el mismo comando `curl`:



```r
sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'
```

Cuando proporcionamos datos para pruebas a SQLMap, debe haber un valor de parámetro que pueda evaluarse para vulnerabilidad SQLi o opciones especializadas para la búsqueda automática de parámetros (por ejemplo, `--crawl`, `--forms` o `-g`).

---

## GET/POST Requests

En el escenario más común, los parámetros `GET` se proporcionan utilizando la opción `-u`/`--url`, como en el ejemplo anterior. Para probar datos `POST`, se puede usar la flag `--data`, de la siguiente manera:



```r
sqlmap 'http://www.example.com/' --data 'uid=1&name=test'
```

En tales casos, los parámetros `POST` `uid` y `name` se probarán para vulnerabilidad SQLi. Por ejemplo, si tenemos una indicación clara de que el parámetro `uid` es vulnerable a SQLi, podríamos limitar las pruebas solo a este parámetro usando `-p uid`. De lo contrario, podríamos marcarlo dentro de los datos proporcionados usando el marcador especial `*` de la siguiente manera:



```r
sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
```

---

## Full HTTP Requests

Si necesitamos especificar una solicitud HTTP compleja con muchos valores de encabezado diferentes y un cuerpo POST prolongado, podemos usar la flag `-r`. Con esta opción, se proporciona a SQLMap el "archivo de solicitud", que contiene toda la solicitud HTTP dentro de un solo archivo de texto. En un escenario común, dicha solicitud HTTP se puede capturar desde una aplicación proxy especializada (por ejemplo, `Burp`) y escribir en el archivo de solicitud, de la siguiente manera:

![burp_request](https://academy.hackthebox.com/storage/modules/58/x7ND6VQ.png)

Un ejemplo de una solicitud HTTP capturada con `Burp` se vería así:


```r
GET /?id=1 HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
DNT: 1
If-Modified-Since: Thu, 17 Oct 2019 07:18:26 GMT
If-None-Match: "3147526947"
Cache-Control: max-age=0
```

Podemos copiar manualmente la solicitud HTTP desde `Burp` y escribirla en un archivo, o podemos hacer clic derecho en la solicitud dentro de `Burp` y elegir `Copy to file`. Otra forma de capturar la solicitud HTTP completa sería usando el navegador, como se mencionó anteriormente, y eligiendo la opción `Copy` > `Copy Request Headers`, y luego pegando la solicitud en un archivo.

Para ejecutar SQLMap con un archivo de solicitud HTTP, usamos la flag `-r`, de la siguiente manera:



```r
sqlmap -r req.txt
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.4.9}
|_ -| . [(]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org


[*] starting @ 14:32:59 /2020-09-11/

[14:32:59] [INFO] parsing HTTP request from 'req.txt'
[14:32:59] [INFO] testing connection to the target URL
[14:32:59] [INFO] testing if the target URL content is stable
[14:33:00] [INFO] target URL content is stable
```

Tip: de manera similar al caso con la opción `--data`, dentro del archivo de solicitud guardado, podemos especificar el parámetro que queremos inyectar con un asterisco (*), como '/?id=*'.

---

## Custom SQLMap Requests

Si quisiéramos crear solicitudes complicadas manualmente, hay numerosos interruptores y opciones para ajustar SQLMap.

Por ejemplo, si hay un requisito para especificar el valor de la cookie (sesión) como `PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c`, se usaría la opción `--cookie` de la siguiente manera:



```r
sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
```

El mismo efecto se puede lograr con el uso de la opción `-H/--header`:



```r
sqlmap ... -H='Cookie:PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
```

Podemos aplicar lo mismo a opciones como `--host`, `--referer` y `-A/--user-agent`, que se utilizan para especificar los valores de los mismos encabezados HTTP.

Además, hay un interruptor `--random-agent` diseñado para seleccionar aleatoriamente un valor de encabezado `User-agent` de la base de datos incluida de valores de navegadores comunes. Este es un interruptor importante a recordar, ya que cada vez más soluciones de protección eliminan automáticamente todo el tráfico HTTP que contiene el valor reconocible predeterminado del User-agent de SQLMap (por ejemplo, `User-agent: sqlmap/1.4.9.12#dev (http://sqlmap.org)`). Alternativamente, se puede usar el interruptor `--mobile` para imitar un smartphone utilizando ese mismo valor de encabezado.

Aunque SQLMap, por defecto, solo apunta a los parámetros HTTP, es posible probar los encabezados para la vulnerabilidad SQLi. La forma más fácil es especificar la marca de inyección "personalizada" después del valor del encabezado (por ejemplo, `--cookie="id=1*"`). El mismo principio se aplica a cualquier otra parte de la solicitud.

Además, si quisiéramos especificar un método HTTP alternativo, además de `GET` y `POST` (por ejemplo, `PUT`), podemos utilizar la opción `--method`, de la siguiente manera:



```r
sqlmap -u www.target.com --data='id=1' --method PUT
```

---

## Custom HTTP Requests

Además del estilo de cuerpo de `POST` form-data más común (por ejemplo, `id=1`), SQLMap también admite solicitudes HTTP en formato JSON (por ejemplo, `{"id":1}`) y en formato XML (por ejemplo, `<element><id>1</id></element>`).

El soporte para estos formatos está implementado de manera "relajada"; por lo tanto, no hay restricciones estrictas sobre cómo se almacenan los valores de los parámetros dentro. En caso de que el cuerpo `POST` sea relativamente simple y corto, la opción `--data` será suficiente.

Sin embargo, en el caso de un cuerpo POST complejo o largo, podemos usar nuevamente la opción `-r`:



```r
cat req.txt
HTTP / HTTP/1.0
Host: www.example.com

{
  "data": [{
    "type": "articles",
    "id": "1",
    "attributes": {
      "title": "Example JSON",
      "body": "Just an example",
      "created": "2020-05-22T14:56:29.000Z",
      "updated": "2020-05-22T14:56:28.000Z"
    },
    "relationships": {
      "author": {
        "data": {"id": "42", "type": "user"}
      }
    }
  }]
}
```



```r
sqlmap -r req.txt
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.4.9}
|_ -| . [)]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org


[*] starting @ 00:03:44 /2020-09-15/

[00:03:44] [INFO] parsing HTTP request from 'req.txt'
JSON data found in HTTP body. Do you want to process it? [Y/n

/q] 
[00:03:45] [INFO] testing connection to the target URL
[00:03:45] [INFO] testing if the target URL content is stable
[00:03:46] [INFO] testing if HTTP parameter 'JSON type' is dynamic
[00:03:46] [WARNING] HTTP parameter 'JSON type' does not appear to be dynamic
[00:03:46] [WARNING] heuristic (basic) test shows that HTTP parameter 'JSON type' might not be injectable
```