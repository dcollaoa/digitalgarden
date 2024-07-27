Hay numerosas formas de detectar intentos de inyección, y hay múltiples métodos para evadir estas detecciones. Demostraremos el concepto de detección y cómo funciona la evasión utilizando Linux como ejemplo. Aprenderemos cómo utilizar estas evasiones y eventualmente seremos capaces de prevenirlas. Una vez que tengamos un buen entendimiento de cómo funcionan, podemos revisar varias fuentes en internet para descubrir otros tipos de evasiones y aprender a mitigarlas.

---

## Bypass Blacklisted Operators

Veremos que la mayoría de los operadores de inyección están realmente en una lista negra. Sin embargo, el carácter de nueva línea generalmente no está en la lista negra, ya que puede ser necesario en el payload. Sabemos que el carácter de nueva línea funciona para agregar nuestros comandos tanto en Linux como en Windows, así que intentemos usarlo como nuestro operador de inyección: ![Filter Operator](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_operator.jpg)

Como podemos ver, aunque nuestro payload incluyó un carácter de nueva línea, nuestra solicitud no fue denegada y obtuvimos la salida del comando `ping`, lo que significa que este carácter no está en la lista negra y podemos usarlo como nuestro operador de inyección. Comencemos discutiendo cómo evadir un carácter comúnmente en la lista negra: un espacio.

---

## Bypass Blacklisted Spaces

Ahora que tenemos un operador de inyección funcional, modifiquemos nuestro payload original y enviémoslo nuevamente como (`127.0.0.1%0a whoami`): ![Filter Space](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_spaces_1.jpg)

Como podemos ver, todavía obtenemos un mensaje de error `invalid input`, lo que significa que aún tenemos otros filtros que evadir. Así que, como hicimos antes, solo agreguemos el siguiente carácter (que es un espacio) y veamos si causó la denegación de la solicitud: ![Filter Space](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_spaces_2.jpg)

Como podemos ver, el carácter de espacio también está en la lista negra. Un espacio es un carácter comúnmente en la lista negra, especialmente si la entrada no debe contener espacios, como una IP, por ejemplo. Sin embargo, hay muchas formas de agregar un carácter de espacio sin usar realmente el carácter de espacio.

### Usando Tabs

Usar tabs (%09) en lugar de espacios es una técnica que puede funcionar, ya que tanto Linux como Windows aceptan comandos con tabs entre argumentos y se ejecutan de la misma manera. Así que intentemos usar un tab en lugar del carácter de espacio (`127.0.0.1%0a%09`) y veamos si nuestra solicitud es aceptada: ![Filter Space](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_spaces_3.jpg)

Como podemos ver, evitamos exitosamente el filtro de caracteres de espacio utilizando un tab en su lugar. Veamos otro método para reemplazar los caracteres de espacio.

### Usando $IFS

Usar la variable de entorno de Linux ($IFS) también puede funcionar, ya que su valor predeterminado es un espacio y un tab, lo cual funcionaría entre argumentos de comando. Entonces, si usamos `${IFS}` donde deberían estar los espacios, la variable debería ser reemplazada automáticamente por un espacio y nuestro comando debería funcionar.

Usemos `${IFS}` y veamos si funciona (`127.0.0.1%0a${IFS}`): ![Filter Space](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_spaces_4.jpg)

Vemos que nuestra solicitud no fue denegada esta vez y evitamos nuevamente el filtro de espacio.

### Usando Brace Expansion

Hay muchos otros métodos que podemos utilizar para evadir los filtros de espacio. Por ejemplo, podemos usar la característica `Bash Brace Expansion`, que automáticamente agrega espacios entre argumentos envueltos entre llaves, de la siguiente manera:

```bash
{ls,-la}

total 0
drwxr-xr-x 1 21y4d 21y4d   0 Jul 13 07:37 .
drwxr-xr-x 1 21y4d 21y4d   0 Jul 13 13:01 ..
```

Como podemos ver, el comando se ejecutó exitosamente sin tener espacios en él. Podemos utilizar el mismo método en las evasiones de filtros de comando, utilizando brace expansion en nuestros argumentos de comando, como (`127.0.0.1%0a{ls,-la}`). Para descubrir más formas de evadir los filtros de espacio, revisa la página de [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space) sobre cómo escribir comandos sin espacios.

**Ejercicio:** Trata de buscar otros métodos para evadir los filtros de espacio y úsalos con la aplicación web `Host Checker` para aprender cómo funcionan.