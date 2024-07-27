En algunos casos, podemos estar lidiando con soluciones avanzadas de filtrado, como Web Application Firewalls (WAFs), y las técnicas básicas de evasión pueden no funcionar necesariamente. Podemos utilizar técnicas más avanzadas para estas ocasiones, que hacen que la detección de los comandos inyectados sea mucho menos probable.

---

## Case Manipulation

Una técnica de ofuscación de comandos que podemos usar es la manipulación de mayúsculas y minúsculas, como invertir las mayúsculas y minúsculas de un comando (por ejemplo, `WHOAMI`) o alternar entre mayúsculas y minúsculas (por ejemplo, `WhOaMi`). Esto generalmente funciona porque una lista negra de comandos puede no verificar las diferentes variaciones de mayúsculas y minúsculas de una sola palabra, ya que los sistemas Linux son sensibles a mayúsculas y minúsculas.

Si estamos tratando con un servidor Windows, podemos cambiar las mayúsculas y minúsculas de los caracteres del comando y enviarlo. En Windows, los comandos para PowerShell y CMD no distinguen entre mayúsculas y minúsculas, lo que significa que ejecutarán el comando sin importar en qué caso esté escrito:

```powershell
PS C:\htb> WhOaMi

21y4d
```

Sin embargo, cuando se trata de Linux y un shell bash, que distinguen entre mayúsculas y minúsculas, como mencionamos anteriormente, tenemos que ser un poco creativos y encontrar un comando que convierta el comando en una palabra completamente en minúsculas. Un comando que funciona es el siguiente:

```bash
21y4d@htb[/htb]$ $(tr "[A-Z]" "[a-z]"<<<"WhOaMi")

21y4d
```

Como podemos ver, el comando funcionó, aunque la palabra que proporcionamos fue (`WhOaMi`). Este comando usa `tr` para reemplazar todos los caracteres en mayúsculas con caracteres en minúsculas, lo que da como resultado un comando con caracteres en minúsculas. Sin embargo, si intentamos usar el comando anterior con la aplicación web `Host Checker`, veremos que aún se bloquea:

### Burp POST Request

![Filter Commands](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_commands_3.jpg)

`¿Puedes adivinar por qué?` Es porque el comando anterior contiene espacios, que es un carácter filtrado en nuestra aplicación web, como hemos visto antes. Entonces, con tales técnicas, `debemos asegurarnos de no usar ningún carácter filtrado`, de lo contrario, nuestras solicitudes fallarán y podríamos pensar que las técnicas no funcionaron.

Una vez que reemplazamos los espacios con tabulaciones (`%09`), vemos que el comando funciona perfectamente:

### Burp POST Request

![Filter Commands](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_commands_4.jpg)

Hay muchos otros comandos que podemos usar para el mismo propósito, como el siguiente:

```bash
$(a="WhOaMi";printf %s "${a,,}")
```

Ejercicio: ¿Puedes probar el comando anterior para ver si funciona en tu VM Linux, y luego intentar evitar usar caracteres filtrados para hacerlo funcionar en la aplicación web?

---

## Reversed Commands

Otra técnica de ofuscación de comandos que discutiremos es invertir comandos y tener una plantilla de comandos que los revierta y los ejecute en tiempo real. En este caso, escribiremos `imaohw` en lugar de `whoami` para evitar activar el comando en la lista negra.

Podemos ser creativos con tales técnicas y crear nuestros propios comandos de Linux/Windows que finalmente ejecuten el comando sin contener nunca las palabras reales del comando. Primero, tendríamos que obtener la cadena invertida de nuestro comando en nuestra terminal, de la siguiente manera:

```bash
echo 'whoami' | rev
imaohw
```

Luego, podemos ejecutar el comando original invirtiéndolo nuevamente en un sub-shell (`$()`), de la siguiente manera:

```bash
21y4d@htb[/htb]$ $(rev<<<'imaohw')

21y4d
```

Vemos que aunque el comando no contiene la palabra `whoami`, funciona igual y proporciona el resultado esperado. También podemos probar este comando con nuestro ejercicio, y realmente funciona:

### Burp POST Request

![Filter Commands](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_commands_5.jpg)

Consejo: Si quisieras evitar un filtro de caracteres con el método anterior, también tendrías que invertirlos, o incluirlos al invertir el comando original.

Lo mismo se puede aplicar en `Windows.` Primero, podemos invertir una cadena, de la siguiente manera:

```powershell
PS C:\htb> "whoami"[-1..-20] -join ''

imaohw
```

Ahora podemos usar el siguiente comando para ejecutar una cadena invertida con un sub-shell de PowerShell (`iex "$()"`), de la siguiente manera:

```powershell
PS C:\htb> iex "$('imaohw'[-1..-20] -join '')"

21y4d
```

---

## Encoded Commands

La técnica final que discutiremos es útil para comandos que contienen caracteres filtrados o caracteres que pueden ser decodificados por URL por el servidor. Esto puede permitir que el comando se desordene cuando llega al shell y finalmente falle al ejecutarse. En lugar de copiar un comando existente en línea, intentaremos crear nuestro propio comando de ofuscación único esta vez. De esta manera, es mucho menos probable que sea denegado por un filtro o un WAF. El comando que creamos será único para cada caso, dependiendo de qué caracteres están permitidos y el nivel de seguridad en el servidor.

Podemos utilizar varias herramientas de codificación, como `base64` (para codificación b64) o `xxd` (para codificación hex). Tomemos `base64` como ejemplo. Primero, codificaremos la carga útil que queremos ejecutar (que incluye caracteres filtrados):

```bash
echo -n 'cat /etc/passwd | grep 33' | base64

Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==
```

Ahora podemos crear un comando que decodifique la cadena codificada en un sub-shell (`$()`), y luego pasarla a `bash` para que se ejecute (es decir, `bash<<<`), de la siguiente manera:

```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)

www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

Como podemos ver, el comando anterior ejecuta el comando perfectamente. No incluimos ningún carácter filtrado y evitamos caracteres codificados que pueden llevar a que el comando falle al ejecutarse.

Consejo: Tenga en cuenta que estamos usando `<<<` para evitar usar una tubería `|`, que es un carácter filtrado.

Ahora podemos usar este comando (una vez que reemplacemos los espacios) para ejecutar el mismo comando a través de inyección de comandos:

### Burp POST Request

![Filter Commands](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_commands_6.jpg)

Incluso si algunos comandos fueron filtrados, como `bash` o `base64`, podríamos evitar ese filtro con las técnicas que discutimos en la sección anterior (por ejemplo, inserción de caracteres), o usar otras alternativas como `sh` para la ejecución de comandos y `openssl` para la decodificación de b64, o `xxd` para la decodificación hex.

Usamos la misma técnica con Windows también. Primero, necesitamos codificar en base64 nuestra cadena, de la siguiente manera:

```powershell
PS C:\htb> [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))

dwBoAG8AYQBtAGkA
```

También podemos lograr lo mismo en Linux, pero tendríamos que convertir la cadena de `utf-8` a `utf-16` antes de `base64`, de la siguiente manera:

```bash
echo -n whoami | iconv -f utf-8 -t utf-16le | base64

dwBoAG8AYQBtAGkA
```

Finalmente, podemos decodificar la cadena b64 y ejecutarla con un sub-shell de PowerShell (`iex "$()"`), de la siguiente manera:

```powershell
PS C:\htb> iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"

21y4d
```

Como podemos ver, podemos ser creativos con `Bash` o `PowerShell` y crear nuevos métodos de bypass y ofuscación que no se hayan utilizado antes, y, por lo tanto, es muy probable que eviten filtros y WAFs. Varias herramientas pueden ayudarnos a ofuscar automáticamente nuestros comandos, que discutiremos en la siguiente sección.

Además de las técnicas que discutimos, podemos utilizar numerosos otros métodos, como comodines, expresiones regulares, redirección de salida, expansión de enteros y muchos otros. Podemos encontrar algunas de estas técnicas en [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-with-variable-expansion).