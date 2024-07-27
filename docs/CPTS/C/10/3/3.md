Explotar vulnerabilidades IDOR es fácil en algunos casos, pero puede ser muy desafiante en otros. Una vez que identificamos un posible IDOR, podemos comenzar a probarlo con técnicas básicas para ver si expone otros datos. En cuanto a los ataques IDOR avanzados, necesitamos entender mejor cómo funciona la aplicación web, cómo calcula sus referencias de objetos y cómo funciona su sistema de control de acceso para poder realizar ataques avanzados que pueden no ser explotables con técnicas básicas.

Empecemos discutiendo varias técnicas para explotar vulnerabilidades IDOR, desde la enumeración básica hasta la recopilación masiva de datos y la escalada de privilegios de usuario.

---

## Insecure Parameters

Comencemos con un ejemplo básico que muestra una típica vulnerabilidad IDOR. El ejercicio a continuación es una aplicación web de `Employee Manager` que alberga registros de empleados:

`http://SERVER_IP:PORT/`

![Employee Manager](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_employee_manager.jpg)

Nuestra aplicación web asume que estamos logueados como un empleado con el user id `uid=1` para simplificar las cosas. Esto requeriría que iniciemos sesión con credenciales en una aplicación web real, pero el resto del ataque sería el mismo. Una vez que hacemos clic en `Documents`, somos redirigidos a `/documents.php`:

`http://SERVER_IP:PORT/documents.php?uid=1`

![Documents](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_documents.jpg)

Cuando llegamos a la página de `Documents`, vemos varios documentos que pertenecen a nuestro usuario. Estos pueden ser archivos subidos por nuestro usuario o archivos configurados para nosotros por otro departamento (por ejemplo, el Departamento de Recursos Humanos). Revisando los enlaces de los archivos, vemos que tienen nombres individuales:

```r
/documents/Invoice_1_09_2021.pdf
/documents/Report_1_10_2021.pdf
```

Vemos que los archivos tienen un patrón de nombres predecible, ya que los nombres de los archivos parecen usar el `uid` del usuario y el mes/año como parte del nombre del archivo, lo que puede permitirnos fuzzear archivos para otros usuarios. Este es el tipo más básico de vulnerabilidad IDOR y se llama `static file IDOR`. Sin embargo, para fuzzear otros archivos con éxito, asumiríamos que todos comienzan con `Invoice` o `Report`, lo que puede revelar algunos archivos, pero no todos. Así que busquemos una vulnerabilidad IDOR más sólida.

Vemos que la página está configurando nuestro `uid` con un parámetro `GET` en la URL como (`documents.php?uid=1`). Si la aplicación web usa este parámetro `uid` GET como una referencia directa a los registros de empleados que debería mostrar, podríamos ver los documentos de otros empleados simplemente cambiando este valor. Si el back-end de la aplicación web tiene un sistema de control de acceso adecuado, obtendremos algún tipo de `Access Denied`. Sin embargo, dado que la aplicación web pasa nuestro `uid` en texto claro como referencia directa, esto puede indicar un diseño deficiente de la aplicación web, lo que lleva a un acceso arbitrario a los registros de empleados.

Cuando intentamos cambiar el `uid` a `?uid=2`, no notamos ninguna diferencia en la salida de la página, ya que seguimos obteniendo la misma lista de documentos y podríamos suponer que aún devuelve nuestros propios documentos:

`http://SERVER_IP:PORT/documents.php?uid=2`

![Documents](https://academy.hackthebox.com/storage/modules/134/web_attacks_idor_documents.jpg)

Sin embargo, `debemos estar atentos a los detalles de la página durante cualquier web pentest` y siempre estar atentos al código fuente y al tamaño de la página. Si revisamos los archivos vinculados, o si hacemos clic en ellos para verlos, notaremos que son archivos diferentes, que parecen ser los documentos pertenecientes al empleado con `uid=2`:

```r
/documents/Invoice_2_08_2020.pdf
/documents/Report_2_12_2020.pdf
```

Este es un error común encontrado en aplicaciones web que sufren de vulnerabilidades IDOR, ya que colocan el parámetro que controla qué documentos de usuario mostrar bajo nuestro control sin tener un sistema de control de acceso en el back-end. Otro ejemplo es usar un parámetro de filtro para mostrar solo los documentos de un usuario específico (por ejemplo, `uid_filter=1`), que también se puede manipular para mostrar los documentos de otros usuarios o incluso eliminarse por completo para mostrar todos los documentos a la vez.

---

## Mass Enumeration

Podemos intentar acceder manualmente a los documentos de otros empleados con `uid=3`, `uid=4`, y así sucesivamente. Sin embargo, acceder manualmente a los archivos no es eficiente en un entorno laboral real con cientos o miles de empleados. Entonces, podemos usar una herramienta como `Burp Intruder` o `ZAP Fuzzer` para recuperar todos los archivos o escribir un pequeño script bash para descargar todos los archivos, que es lo que haremos.

Podemos hacer clic en [`CTRL+SHIFT+C`] en Firefox para habilitar el `element inspector`, y luego hacer clic en cualquiera de los enlaces para ver su código fuente HTML, y obtendremos lo siguiente:

```r
<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```

Podemos elegir cualquier palabra única para poder `grep` el enlace del archivo. En nuestro caso, vemos que cada enlace comienza con `<li class='pure-tree_link'>`, por lo que podemos `curl` la página y `grep` esta línea, de la siguiente manera:

```r
curl -s "http://SERVER_IP:PORT/documents.php?uid=1" | grep "<li class='pure-tree_link'>"

<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```

Como podemos ver, pudimos capturar los enlaces de los documentos con éxito. Ahora podemos usar comandos específicos de bash para recortar las partes adicionales y obtener solo los enlaces de los documentos en la salida. Sin embargo, es una mejor práctica usar un patrón `Regex` que coincida con las cadenas entre `/document` y `.pdf`, que podemos usar con `grep` para obtener solo los enlaces de los documentos, de la siguiente manera:

```r
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"

/documents/Invoice_3_06_2020.pdf
/documents/Report_3_01_2020.pdf
```

Ahora, podemos usar un simple `for` loop para recorrer el parámetro `uid` y devolver el documento de todos los empleados, y luego usar `wget` para descargar cada enlace de documento:

```r
#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
        for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
                wget -q $url/$link
        done
done
```

Cuando ejecutamos el script, descargará todos los documentos de todos los empleados con `uids` entre 1-10, explotando con éxito la vulnerabilidad IDOR para enumerar en masa los documentos de todos los empleados. Este script es un ejemplo de cómo podemos lograr el mismo objetivo. Intenta usar una herramienta como Burp Intruder o ZAP Fuzzer, o escribe otro script en Bash o PowerShell para descargar todos los documentos.