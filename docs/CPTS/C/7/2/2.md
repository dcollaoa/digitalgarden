En la sección anterior, vimos varios tipos de ataques que podemos utilizar para diferentes tipos de vulnerabilidades LFI. En muchos casos, podemos estar frente a una aplicación web que aplica varias protecciones contra la inclusión de archivos, por lo que nuestros payloads LFI normales no funcionarían. Aun así, a menos que la aplicación web esté adecuadamente asegurada contra la entrada de usuarios maliciosos en LFI, podemos ser capaces de evadir las protecciones establecidas y alcanzar la inclusión de archivos.

---

## Non-Recursive Path Traversal Filters

Uno de los filtros más básicos contra LFI es un filtro de búsqueda y reemplazo, donde simplemente elimina subcadenas de (`../`) para evitar la transversal de rutas. Por ejemplo:


```r
$language = str_replace('../', '', $_GET['language']);
```

El código anterior se supone que previene la transversal de rutas y, por lo tanto, hace inútil el LFI. Si probamos los payloads LFI que intentamos en la sección anterior, obtenemos lo siguiente:

 `http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/passwd`

![](https://academy.hackthebox.com/storage/modules/23/lfi_blacklist.png)

Vemos que todas las subcadenas `../` fueron eliminadas, lo que resultó en una ruta final de `./languages/etc/passwd`. Sin embargo, este filtro es muy inseguro, ya que no está eliminando `recursivamente` la subcadena `../`, ya que se ejecuta una sola vez en la cadena de entrada y no aplica el filtro en la cadena de salida. Por ejemplo, si usamos `....//` como nuestro payload, entonces el filtro eliminaría `../` y la cadena de salida sería `../`, lo que significa que aún podemos realizar la transversal de rutas. Intentemos aplicar esta lógica para incluir `/etc/passwd` nuevamente:

   
`http://<SERVER_IP>:<PORT>/index.php?language=....//....//....//....//etc/passwd`

![](https://academy.hackthebox.com/storage/modules/23/lfi_blacklist_passwd.png)

Como podemos ver, la inclusión fue exitosa esta vez, y pudimos leer `/etc/passwd` con éxito. La subcadena `....//` no es la única evasión que podemos usar, ya que podemos usar `..././` o `....\/` y varios otros payloads LFI recursivos. Además, en algunos casos, escapar el carácter de barra diagonal también puede funcionar para evitar los filtros de transversal de rutas (e.g. `....\/`), o agregar barras diagonales adicionales (e.g. `....////`).

---

## Encoding

Algunos filtros web pueden prevenir entradas que incluyan ciertos caracteres relacionados con LFI, como un punto `.` o una barra diagonal `/` utilizados para la transversal de rutas. Sin embargo, algunos de estos filtros pueden ser evadidos codificando en URL nuestra entrada, de manera que ya no incluya estos caracteres malos, pero aún se decodifique de nuevo en nuestra cadena de transversal de rutas una vez que llegue a la función vulnerable. Los filtros principales de PHP en las versiones 5.3.4 y anteriores eran específicamente vulnerables a esta evasión, pero incluso en versiones más recientes podemos encontrar filtros personalizados que pueden ser evadidos a través de la codificación en URL.

Si la aplicación web objetivo no permitía `.` y `/` en nuestra entrada, podemos codificar en URL `../` en `%2e%2e%2f`, lo que puede evadir el filtro. Para hacerlo, podemos usar cualquier utilidad en línea de codificación en URL o usar la herramienta Burp Suite Decoder, como se muestra: ![burp_url_encode](https://academy.hackthebox.com/storage/modules/23/burp_url_encode.jpg)

**Nota:** Para que esto funcione, debemos codificar en URL todos los caracteres, incluidos los puntos. Algunos codificadores de URL pueden no codificar puntos ya que se consideran parte del esquema de la URL.

Intentemos usar este payload LFI codificado contra nuestra aplicación web vulnerable anterior que filtra cadenas `../`:

   
`<SERVER_IP>:<PORT>/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64`

![](https://academy.hackthebox.com/storage/modules/23/lfi_blacklist_passwd_filter.png)

Como podemos ver, también pudimos evadir con éxito el filtro y usar la transversal de rutas para leer `/etc/passwd`. Además, podemos usar Burp Decoder para codificar la cadena codificada una vez más para tener una cadena `double encoded`, lo que también puede evadir otros tipos de filtros.

Puedes referirte al módulo de [Command Injections](https://academy.hackthebox.com/module/details/109) para más información sobre cómo evadir varios caracteres en listas negras, ya que las mismas técnicas pueden ser utilizadas con LFI.

---

## Approved Paths

Algunas aplicaciones web también pueden usar expresiones regulares para asegurarse de que el archivo que se incluye esté bajo una ruta específica. Por ejemplo, la aplicación web con la que hemos estado tratando puede aceptar solo rutas que estén bajo el directorio `./languages`, de la siguiente manera:


```r
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
} else {
    echo 'Illegal path specified!';
}
```

Para encontrar la ruta aprobada, podemos examinar las solicitudes enviadas por los formularios existentes y ver qué ruta usan para la funcionalidad web normal. Además, podemos fuzzear directorios web bajo la misma ruta, e intentar diferentes hasta encontrar una coincidencia. Para evadir esto, podemos usar la transversal de rutas y comenzar nuestro payload con la ruta aprobada, y luego usar `../` para volver al directorio raíz y leer el archivo que especificamos, de la siguiente manera:

   
`<SERVER_IP>:<PORT>/index.php?language=./languages/../../../../etc/passwd`

![](https://academy.hackthebox.com/storage/modules/23/lfi_blacklist_passwd_filter.png)

Algunas aplicaciones web pueden aplicar este filtro junto con uno de los filtros anteriores, por lo que podemos combinar ambas técnicas comenzando nuestro payload con la ruta aprobada, y luego codificando en URL nuestro payload o usando un payload recursivo.

**Nota:** Todas las técnicas mencionadas hasta ahora deberían funcionar con cualquier vulnerabilidad LFI, independientemente del lenguaje de desarrollo o framework utilizado en el backend.

---

## Appended Extension

Como se discutió en la sección anterior, algunas aplicaciones web agregan una extensión a nuestra cadena de entrada (e.g. `.php`), para asegurarse de que el archivo que incluimos tenga la extensión esperada. Con versiones modernas de PHP, puede que no podamos evadir esto y estemos restringidos a solo leer archivos con esa extensión, lo que aún puede ser útil, como veremos en la siguiente sección (e.g. para leer código fuente).

Hay un par de otras técnicas que podemos usar, pero son `obsoletas con versiones modernas de PHP y solo funcionan con versiones de PHP anteriores a 5.3/5.4`. Sin embargo, aún puede ser beneficioso mencionarlas, ya que algunas aplicaciones web pueden seguir ejecutándose en servidores antiguos, y estas técnicas pueden ser las únicas evasiones posibles.

### Path Truncation

En versiones anteriores de PHP, las cadenas definidas tenían una longitud máxima de 4096 caracteres, probablemente debido a la limitación de sistemas de 32 bits. Si se pasa una cadena más larga, simplemente será `truncada`, y cualquier carácter después de la longitud máxima será ignorado. Además, PHP también solía eliminar las barras diagonales finales y los puntos únicos en los nombres de ruta, por lo que si llamamos (`/etc/passwd/.`) entonces el `/.` también sería truncado, y PHP llamaría (`/etc/passwd`). PHP, y los sistemas Linux en general, también desprecian múltiples barras diagonales en la ruta (e.g. `////etc/passwd` es lo mismo que `/etc/passwd`). De manera similar, un acceso directo al directorio actual (`.`) en el medio de la ruta también sería desestimado (e.g. `/etc/./passwd`).

Si combinamos ambas limitaciones de PHP, podemos crear cadenas muy largas que se evalúan a una ruta correcta. Cada vez que alcanzamos la limitación de 4096 caracteres, la extensión agregada (`.php`) sería truncada, y tendríamos una ruta sin una extensión agregada. Finalmente, también es importante señalar que también necesitaríamos `comenzar la ruta con un directorio no existente` para que esta técnica funcione.

Un ejemplo de tal payload sería el siguiente:


```r
?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]
```

Por supuesto, no tenemos que escribir manualmente `./` 2048 veces (total de 4096 caracteres), pero podemos automatizar la creación de esta cadena con el siguiente comando:



```r
echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
non_existing_directory/../../../etc/passwd/./././<SNIP>././././
```

También podemos aumentar la cantidad de `../`, ya que agregar más aún nos llevaría al directorio raíz, como se explicó en la sección anterior. Sin embargo, si usamos este método, deberíamos calcular la longitud total de la cadena para asegurarnos de

 que solo `.php` se trunque y no nuestro archivo solicitado al final de la cadena (`/etc/passwd`). Es por eso que sería más fácil usar el primer método.

### Null Bytes

Las versiones de PHP anteriores a 5.5 eran vulnerables a la `injection de null byte`, lo que significa que agregar un null byte (`%00`) al final de la cadena terminaría la cadena y no consideraría nada después de ella. Esto se debe a cómo se almacenan las cadenas en la memoria de bajo nivel, donde las cadenas en memoria deben usar un null byte para indicar el final de la cadena, como se ve en los lenguajes Assembly, C o C++.

Para explotar esta vulnerabilidad, podemos terminar nuestro payload con un null byte (e.g. `/etc/passwd%00`), de manera que la ruta final pasada a `include()` sería (`/etc/passwd%00.php`). De esta manera, aunque `.php` se agregue a nuestra cadena, cualquier cosa después del null byte sería truncada, y por lo tanto la ruta utilizada sería `/etc/passwd`, llevándonos a evadir la extensión agregada.