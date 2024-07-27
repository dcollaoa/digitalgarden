Además de los operadores de inyección y los caracteres de espacio, un carácter muy común en la lista negra es la barra diagonal (`/`) o la barra invertida (`\`), ya que es necesario especificar directorios en Linux o Windows. Podemos utilizar varias técnicas para producir cualquier personaje que queramos evitando el uso de personajes de la lista negra.
## Linux

Hay varias técnicas que podemos utilizar para tener slashes en nuestro payload. Una técnica que podemos usar para reemplazar slashes (u otros caracteres) es a través de `Linux Environment Variables`, como hicimos con `${IFS}`. Mientras `${IFS}` se reemplaza directamente por un espacio, no hay una variable de entorno para slashes o puntos y comas. Sin embargo, estos caracteres pueden usarse en una variable de entorno, y podemos especificar `start` y `length` de nuestra cadena para que coincida exactamente con este carácter.

Por ejemplo, si miramos la variable de entorno `$PATH` en Linux, podría verse algo así:

```r
echo ${PATH}

/usr/local/bin:/usr/bin:/bin:/usr/games
```

Entonces, si comenzamos en el carácter `0` y tomamos solo una cadena de longitud `1`, terminaremos con solo el carácter `/`, que podemos usar en nuestro payload:

```r
echo ${PATH:0:1}

/
```

**Nota:** Cuando usamos el comando anterior en nuestro payload, no agregaremos `echo`, ya que solo lo estamos usando en este caso para mostrar el carácter resultante.

Podemos hacer lo mismo con las variables de entorno `$HOME` o `$PWD` también. También podemos usar el mismo concepto para obtener un carácter de punto y coma, que se usará como operador de inyección. Por ejemplo, el siguiente comando nos da un punto y coma:

```r
echo ${LS_COLORS:10:1}

;
```

Ejercicio: Trata de entender cómo el comando anterior resultó en un punto y coma, y luego úsalo en el payload como operador de inyección. Pista: El comando `printenv` imprime todas las variables de entorno en Linux, por lo que puedes ver cuáles pueden contener caracteres útiles, y luego intentar reducir la cadena a ese carácter solo.

Entonces, intentemos usar variables de entorno para agregar un punto y coma y un espacio a nuestro payload (`127.0.0.1${LS_COLORS:10:1}${IFS}`) como nuestro payload, y ver si podemos evitar el filtro: ![Filter Operator](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_spaces_5.jpg)

Como podemos ver, esta vez también logramos evitar el filtro de caracteres.

---

## Windows

El mismo concepto funciona en Windows también. Por ejemplo, para producir un slash en `Windows Command Line (CMD)`, podemos `echo` una variable de Windows (`%HOMEPATH%` -> `\Users\htb-student`), y luego especificar una posición de inicio (`~6` -> `\htb-student`), y finalmente especificar una posición final negativa, que en este caso es la longitud del nombre de usuario `htb-student` (`-11` -> `\`):

```r
C:\htb> echo %HOMEPATH:~6,-11%

\
```

Podemos lograr lo mismo usando las mismas variables en `Windows PowerShell`. Con PowerShell, una palabra se considera un array, por lo que tenemos que especificar el índice del carácter que necesitamos. Como solo necesitamos un carácter, no tenemos que especificar las posiciones de inicio y fin:

```r
PS C:\htb> $env:HOMEPATH[0]

\

PS C:\htb> $env:PROGRAMFILES[10]
PS C:\htb>
```

También podemos usar el comando `Get-ChildItem Env:` de PowerShell para imprimir todas las variables de entorno y luego elegir una de ellas para producir un carácter que necesitemos. `Trata de ser creativo y encontrar diferentes comandos para producir caracteres similares.`

---

## Character Shifting

Hay otras técnicas para producir los caracteres requeridos sin usarlos, como `shifting characters`. Por ejemplo, el siguiente comando de Linux desplaza el carácter que pasamos por `1`. Entonces, todo lo que tenemos que hacer es encontrar el carácter en la tabla ASCII que está justo antes del carácter que necesitamos (podemos obtenerlo con `man ascii`), luego agregarlo en lugar de `[` en el ejemplo a continuación. De esta manera, el último carácter impreso sería el que necesitamos:

```r
man ascii     # \ is on 92, before it is [ on 91
echo $(tr '!-}' '"-~'<<<[)

\
```

Podemos usar comandos de PowerShell para lograr el mismo resultado en Windows, aunque pueden ser mucho más largos que los de Linux.

Ejercicio: Intenta usar la técnica de shifting characters para producir un carácter de punto y coma `;`. Primero encuentra el carácter antes de él en la tabla ASCII, y luego úsalo en el comando anterior.