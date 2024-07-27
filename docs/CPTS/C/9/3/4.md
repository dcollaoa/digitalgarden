Hemos discutido varios métodos para evadir filtros de caracteres únicos. Sin embargo, existen diferentes métodos cuando se trata de evadir comandos en la blacklist. Una blacklist de comandos generalmente consiste en un conjunto de palabras, y si podemos ofuscar nuestros comandos y hacer que se vean diferentes, podríamos ser capaces de evadir los filtros.

Existen varios métodos de ofuscación de comandos que varían en complejidad, como mencionaremos más adelante con herramientas de ofuscación de comandos. Cubriremos algunas técnicas básicas que pueden permitirnos cambiar el aspecto de nuestro comando para evadir los filtros manualmente.

---

## Commands Blacklist

Hasta ahora hemos evadido con éxito el filtro de caracteres para los caracteres de espacio y punto y coma en nuestro payload. Entonces, volvamos a nuestro primer payload y re-agreguemos el comando `whoami` para ver si se ejecuta: ![Filter Commands](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_commands_1.jpg)

Vemos que, aunque usamos caracteres que no son bloqueados por la aplicación web, la solicitud se bloquea nuevamente una vez que agregamos nuestro comando. Esto se debe probablemente a otro tipo de filtro, que es un filtro de blacklist de comandos.

Un filtro de blacklist de comandos básico en `PHP` se vería de la siguiente manera:

```r
$blacklist = ['whoami', 'cat', ...SNIP...];
foreach ($blacklist as $word) {
    if (strpos('$_POST['ip']', $word) !== false) {
        echo "Invalid input";
    }
}
```

Como podemos ver, está revisando cada palabra de la entrada del usuario para ver si coincide con alguna de las palabras en la blacklist. Sin embargo, este código está buscando una coincidencia exacta del comando proporcionado, por lo que si enviamos un comando ligeramente diferente, es posible que no sea bloqueado. Afortunadamente, podemos utilizar varias técnicas de ofuscación que ejecutarán nuestro comando sin usar la palabra exacta del comando.

---

## Linux & Windows

Una técnica de ofuscación muy común y fácil es insertar ciertos caracteres dentro de nuestro comando que generalmente son ignorados por shells de comando como `Bash` o `PowerShell` y ejecutarán el mismo comando como si no estuvieran allí. Algunos de estos caracteres son comilla simple `'` y comilla doble `"`, además de algunos otros.

Los más fáciles de usar son las comillas, y funcionan tanto en servidores Linux como Windows. Por ejemplo, si queremos ofuscar el comando `whoami`, podemos insertar comillas simples entre sus caracteres, de la siguiente manera:

```r
21y4d@htb[/htb]$ w'h'o'am'i

21y4d
```

Lo mismo funciona con comillas dobles también:

```r
21y4d@htb[/htb]$ w"h"o"am"i

21y4d
```

Las cosas importantes a recordar son que `no podemos mezclar tipos de comillas` y `el número de comillas debe ser par`. Podemos probar uno de los anteriores en nuestro payload (`127.0.0.1%0aw'h'o'am'i`) y ver si funciona:

### Burp POST Request

![Filter Commands](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_commands_2.jpg)

Como podemos ver, este método efectivamente funciona.

---

## Linux Only

Podemos insertar algunos otros caracteres exclusivos de Linux en el medio de los comandos, y el shell `bash` los ignorará y ejecutará el comando. Estos caracteres incluyen la barra invertida `\` y el carácter de parámetro posicional `$@`. Esto funciona exactamente como lo hizo con las comillas, pero en este caso, `el número de caracteres no tiene que ser par`, y podemos insertar solo uno de ellos si queremos:

```r
who$@ami
w\ho\am\i
```

Ejercicio: Prueba los dos ejemplos anteriores en tu payload y ve si funcionan para evadir el filtro de comandos. Si no lo hacen, esto puede indicar que has usado un carácter filtrado. ¿Podrías evadir eso también, usando las técnicas que aprendimos en la sección anterior?

---

## Windows Only

También hay algunos caracteres exclusivos de Windows que podemos insertar en el medio de los comandos que no afectan el resultado, como el carácter de intercalación (`^`), como podemos ver en el siguiente ejemplo:

```r
C:\htb> who^ami

21y4d
```

En la siguiente sección, discutiremos algunas técnicas más avanzadas para la ofuscación de comandos y la evasión de filtros.