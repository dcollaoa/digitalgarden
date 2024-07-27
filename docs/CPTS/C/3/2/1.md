Encontramos un host inusual en la red durante nuestro black box penetration test y lo examinamos más de cerca. Descubrimos un servidor web que está ejecutándose en un puerto no estándar. Muchos servidores web o contenidos individuales en los servidores web aún suelen utilizar el esquema de [Basic HTTP AUTH](https://tools.ietf.org/html/rfc7617). Como en nuestro caso, encontramos un servidor web con una ruta que debería despertar cierta curiosidad.

La especificación HTTP proporciona dos mecanismos de autenticación paralelos:

1. `Basic HTTP AUTH` se utiliza para autenticar al usuario ante el servidor HTTP.
2. `Proxy Server Authentication` se utiliza para autenticar al usuario ante un servidor proxy intermedio.

Estos dos mecanismos funcionan de manera muy similar ya que utilizan solicitudes, códigos de estado de respuesta y encabezados de respuesta. Sin embargo, hay diferencias en los códigos de estado y nombres de los encabezados utilizados.

El esquema de Basic HTTP Authentication utiliza ID de usuario y contraseña para la autenticación. El cliente envía una solicitud sin información de autenticación en su primera solicitud. La respuesta del servidor contiene el campo de encabezado `WWW-Authenticate`, que solicita al cliente que proporcione las credenciales. Este campo de encabezado también define detalles de cómo debe llevarse a cabo la autenticación. Se le pide al cliente que envíe la información de autenticación. En su respuesta, el servidor transmite el llamado realm, una cadena de caracteres que le dice al cliente quién está solicitando los datos. El cliente utiliza el método Base64 para codificar el identificador y la contraseña. Esta cadena de caracteres codificada se transmite al servidor en el campo de encabezado Authorization.

`http://www.inlanefreight.htb:31099/webadmin/`

![](https://academy.hackthebox.com/storage/modules/57/bruteforcing_401.jpg)

Como no tenemos credenciales, ni tenemos otros puertos disponibles, ni servicios o información sobre el servidor web para poder usar o atacar, la única opción que queda es utilizar password brute-forcing.

Hay varios tipos de ataques de contraseñas, tales como:

|**Password Attack Type**|
|---|
|`Dictionary attack`|
|`Brute force`|
|`Traffic interception`|
|`Man In the Middle`|
|`Key Logging`|
|`Social engineering`|

Nos centraremos principalmente en `Brute Force` y `Dictionary Attacks`. Ambos ataques encontrarán la contraseña mediante `brute forcing` del servicio.

---

## Brute Force Attack

Un `Brute Force Attack` no depende de una wordlist de contraseñas comunes, sino que funciona probando todas las combinaciones de caracteres posibles para la longitud que especificamos. Por ejemplo, si especificamos la longitud de la contraseña como `4`, probaría todas las claves desde `aaaa` hasta `zzzz`, literalmente `brute forcing` todos los caracteres para encontrar una contraseña funcional.

Sin embargo, incluso si solo usamos caracteres en minúsculas del inglés, esto tendría casi medio millón de permutaciones -`26x26x26x26 = 456,976`-, lo cual es un número enorme, a pesar de que solo tenemos una longitud de contraseña de `4`.

Una vez que la longitud de la contraseña comienza a aumentar, y comenzamos a probar con combinaciones de mayúsculas y minúsculas, números y caracteres especiales, el tiempo que tomaría brute force estas contraseñas puede llevar millones de años.

Todo esto muestra que depender completamente de ataques de fuerza bruta no es ideal, y esto es especialmente cierto para los ataques de brute-forcing que se realizan a través de la red, como en `hydra`.  
Es por eso que deberíamos considerar métodos que puedan aumentar nuestras probabilidades de adivinar la contraseña correcta, como los `Dictionary Attacks`.

---

## Dictionary Attack

Un `Dictionary Attack` intenta adivinar contraseñas con la ayuda de listas. El objetivo es utilizar una lista de contraseñas conocidas para adivinar una contraseña desconocida. Este método es útil siempre que se pueda suponer que se utilizan contraseñas con combinaciones de caracteres razonables.

Afortunadamente, hay una gran cantidad de listas de contraseñas, que consisten en las contraseñas más comúnmente utilizadas encontradas en pruebas y filtraciones de bases de datos.

Podemos revisar el repositorio de [SecLists](https://github.com/danielmiessler/SecLists) para wordlists, ya que tiene una gran variedad de wordlists, cubriendo muchos tipos de ataques.  
Podemos encontrar listas de contraseñas en nuestro PwnBox en `/opt/useful/SecLists/Passwords/`, y listas de nombres de usuario en `/opt/useful/SecLists/Usernames/`.

---

## Methods of Brute Force Attacks

Hay muchas metodologías para llevar a cabo Login Brute Force attacks:

|**Attack**|**Description**|
|---|---|
|Online Brute Force Attack|Atacando una aplicación en vivo a través de la red, como HTTP, HTTPs, SSH, FTP y otros|
|Offline Brute Force Attack|También conocido como Offline Password Cracking, donde intentas crackear un hash de una contraseña encriptada.|
|Reverse Brute Force Attack|También conocido como username brute-forcing, donde intentas una contraseña común con una lista de nombres de usuario en un servicio determinado.|
|Hybrid Brute Force Attack|Atacando a un usuario mediante la creación de una wordlist personalizada de contraseñas, construida utilizando inteligencia conocida sobre el usuario o el servicio.|