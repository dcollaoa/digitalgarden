Como hemos visto en la sección anterior, incluso si los desarrolladores intentan asegurar la aplicación web contra inyecciones, aún puede ser explotable si no fue codificada de manera segura. Otro tipo de mitigación de inyecciones es utilizar caracteres y palabras en la lista negra en el back-end para detectar intentos de inyección y negar la solicitud si esta contiene alguno de ellos. Otra capa adicional a esto es utilizar Web Application Firewalls (WAFs), los cuales pueden tener un alcance más amplio y varios métodos de detección de inyecciones y prevenir otros ataques como SQL injections o ataques XSS.

Esta sección verá algunos ejemplos de cómo se pueden detectar y bloquear las command injections y cómo podemos identificar qué está siendo bloqueado.

---

## Filter/WAF Detection

Comencemos visitando la aplicación web en el ejercicio al final de esta sección. Vemos la misma aplicación web `Host Checker` que hemos estado explotando, pero ahora tiene algunas mitigaciones. Podemos ver que si probamos los operadores anteriores que probamos, como (`;`, `&&`, `||`), obtenemos el mensaje de error `invalid input`: ![Filter](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_1.jpg)

Esto indica que algo que enviamos activó un mecanismo de seguridad que negó nuestra solicitud. Este mensaje de error puede mostrarse de varias maneras. En este caso, lo vemos en el campo donde se muestra la salida, lo que significa que fue detectado y prevenido por la aplicación web en `PHP`. `Si el mensaje de error mostrara una página diferente, con información como nuestra IP y nuestra solicitud, esto podría indicar que fue denegada por un WAF`.

Veamos el payload que enviamos:

```r
127.0.0.1; whoami
```

Aparte de la IP (que sabemos que no está en la lista negra), enviamos:

1. Un carácter de punto y coma `;`
2. Un carácter de espacio
3. Un comando `whoami`

Entonces, la aplicación web `detectó un carácter en la lista negra` o `detectó un comando en la lista negra`, o ambos. Veamos cómo evitar cada uno.

---

## Blacklisted Characters

Una aplicación web puede tener una lista de caracteres en la lista negra, y si el comando los contiene, denegaría la solicitud. El código en `PHP` puede verse algo así:

```r
$blacklist = ['&', '|', ';', ...SNIP...];
foreach ($blacklist as $character) {
    if (strpos($_POST['ip'], $character) !== false) {
        echo "Invalid input";
    }
}
```

Si cualquier carácter en la cadena que enviamos coincide con un carácter en la lista negra, nuestra solicitud es denegada. Antes de comenzar nuestros intentos de eludir el filtro, debemos intentar identificar qué carácter causó la solicitud denegada.

---

## Identifying Blacklisted Character

Reduzcamos nuestra solicitud a un carácter a la vez y veamos cuándo es bloqueado. Sabemos que el payload (`127.0.0.1`) funciona, así que comencemos agregando el punto y coma (`127.0.0.1;`): ![Filter Character](https://academy.hackthebox.com/storage/modules/109/cmdinj_filters_2.jpg)

Seguimos obteniendo un error de `invalid input`, lo que significa que un punto y coma está en la lista negra. Veamos si todos los operadores de inyección que discutimos anteriormente están en la lista negra.