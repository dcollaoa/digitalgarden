`LDAP` (Lightweight Directory Access Protocol) es un protocolo usado para acceder y gestionar información de directorios. Un `directory` es un almacén de datos jerárquico que contiene información sobre recursos de red como `users`, `groups`, `computers`, `printers` y otros dispositivos. LDAP proporciona algunas funcionalidades excelentes:

| **Funcionalidad**         | **Descripción**                                                                                                                                                                                                                       |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Efficient`               | Consultas y conexiones a servicios de directorio rápidas y eficientes, gracias a su lenguaje de consulta simple y almacenamiento de datos no normalizado.                                                                              |
| `Global naming model`     | Soporta múltiples directorios independientes con un modelo de nombres global que asegura entradas únicas.                                                                                                                             |
| `Extensible and flexible` | Esto ayuda a satisfacer requisitos futuros y locales permitiendo atributos y esquemas personalizados.                                                                                                                                 |
| `Compatibility`           | Es compatible con muchos productos de software y plataformas ya que opera sobre TCP/IP y SSL directamente, y es `platform-independent`, adecuado para uso en entornos heterogéneos con diversos sistemas operativos.                  |
| `Authentication`          | Provee mecanismos de `authentication` que permiten a los `users` iniciar sesión una vez y acceder a múltiples recursos en el `server` de manera segura.                                                                                |

Sin embargo, también enfrenta algunos problemas significativos:

| Funcionalidad | Descripción                                                                                                                                                                                                                                                      |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Compliance`  | Los `directory servers` deben ser LDAP compliant para que el servicio se pueda desplegar, lo que puede limitar la elección de proveedores y productos.                                                                                                           |
| `Complexity`  | Difícil de usar y entender para muchos desarrolladores y administradores, que pueden no saber cómo configurar correctamente los `LDAP clients` o usarlo de manera segura.                                                                                        |
| `Encryption`  | LDAP no encripta su tráfico por defecto, lo que expone datos sensibles a posibles interceptaciones y manipulaciones. LDAPS (LDAP sobre SSL) o StartTLS deben usarse para habilitar la encriptación.                                                              |
| `Injection`   | Vulnerable a ataques de `LDAP injection`, donde `users` malintencionados pueden manipular consultas LDAP y obtener `unauthorised access` a datos o recursos. Para prevenir tales ataques, se debe implementar la validación de entrada y codificación de salida. |

LDAP es comúnmente usado para proporcionar una ubicación central para `accessing` y `managing` `directory services`. `Directory services` son colecciones de información sobre la organización, sus `users`, y activos como usernames y passwords. LDAP permite a las organizaciones almacenar, gestionar y asegurar esta información de manera estandarizada. Aquí están algunos casos de uso comunes:

|**Caso de Uso**|**Descripción**|
|---|---|
|`Authentication`|LDAP se puede usar para `central authentication`, permitiendo a los `users` tener credenciales de inicio de sesión únicas a través de múltiples aplicaciones y sistemas. Este es uno de los casos de uso más comunes para LDAP.|
|`Authorisation`|LDAP puede `manage permissions` y `access control` para recursos de red como carpetas o archivos en una red compartida. Sin embargo, esto puede requerir configuración adicional o integración con protocolos como Kerberos.|
|`Directory Services`|LDAP proporciona una manera de `search`, `retrieve`, y `modify data` almacenados en un `directory`, lo que lo hace útil para gestionar grandes cantidades de `users` y dispositivos en una red corporativa. LDAP is based on the X.500 standard para `directory services`.|
|`Synchronisation`|LDAP se puede usar para mantener datos consistentes a través de múltiples sistemas replicando cambios realizados en un `directory` a otro.|

Hay dos implementaciones populares de LDAP: `OpenLDAP`, un software de código abierto ampliamente utilizado y soportado, y `Microsoft Active Directory`, una implementación basada en Windows que se integra sin problemas con otros productos y servicios de Microsoft.

Aunque LDAP y AD están `related`, sirven diferentes propósitos. LDAP es un protocolo que especifica el método de acceso y modificación de `directory services`, mientras que AD es un `directory service` que almacena y gestiona datos de `users` y `computers`. Mientras que LDAP puede comunicarse con AD y otros `directory services`, no es un `directory service` en sí. AD ofrece funcionalidades adicionales como administración de políticas, `single sign-on`, e integración con varios productos de Microsoft.

|**LDAP**|**Active Directory (AD)**|
|---|---|
|Un protocolo que define cómo `clients` y `servers` se comunican entre sí para acceder y manipular datos almacenados en un `directory service`.|Un `directory server` que utiliza LDAP como uno de sus protocolos para proporcionar `authentication`, `authorisation`, y otros servicios para redes basadas en Windows.|
|Un protocolo abierto y multiplataforma que se puede usar con diferentes tipos de `directory servers` y aplicaciones.|Software propietario que solo funciona con sistemas basados en Windows y requiere componentes adicionales como DNS (Domain Name System) y Kerberos para su funcionalidad.|
|Tiene un esquema flexible y extensible que permite a los administradores o desarrolladores definir atributos y clases de objeto personalizados.|Tiene un esquema predefinido que sigue y extiende el estándar X.500 con clases de objeto y atributos adicionales específicos para entornos Windows. Las modificaciones deben hacerse con cautela y cuidado.|
|Soporta múltiples mecanismos de `authentication` como simple bind, SASL, etc.|Soporta Kerberos como su mecanismo de `authentication` primario pero también soporta NTLM (NT LAN Manager) y LDAP sobre SSL/TLS para compatibilidad con versiones anteriores.|

LDAP funciona utilizando una arquitectura `client-server`. Un `client` envía una solicitud LDAP a un `server`, que busca en el `directory service` y devuelve una respuesta al `client`. LDAP es un protocolo más simple y eficiente que X.500, sobre el cual está basado. Utiliza un modelo `client-server`, donde los `clients` envían solicitudes a los `servers` utilizando mensajes LDAP codificados en ASN.1 (Abstract Syntax Notation One) y transmitidos sobre TCP/IP (Transmission Control Protocol/Internet Protocol). Los `servers` procesan las solicitudes y envían respuestas utilizando el mismo formato. LDAP soporta diversas solicitudes, como `bind`, `unbind`, `search`, `compare`, `add`, `delete`, `modify`, etc.

Las solicitudes LDAP son `messages` que los `clients` envían a los `servers` para realizar operaciones sobre datos almacenados en un `directory service`. Una solicitud LDAP consta de varios componentes:

1. `Session connection`: El `client` se conecta al `server` a través de un puerto LDAP (generalmente 389 o 636).
2. `Request type`: El `client` especifica la operación que desea realizar, como `bind`, `search`, etc.
3. `Request parameters`: El `client` proporciona información adicional para la solicitud, como el `distinguished name` (DN) de la entrada a ser accedida o modificada, el alcance y filtro de la consulta de búsqueda, los atributos y valores a ser agregados o cambiados, etc.
4. `Request ID`: El `client` asigna un identificador único para cada solicitud para coincidir con la respuesta correspondiente del `server`.

Una vez que el `server` recibe la solicitud, la procesa y envía de vuelta un mensaje de respuesta que incluye varios componentes:

1. `Response type`: El `server` indica la operación que se realizó en respuesta a la solicitud.
2. `Result code`: El `server` indica si la operación fue exitosa y por qué.
3. `Matched DN:` Si corresponde, el `server` devuelve el DN de la entrada existente más cercana que coincide con la solicitud.
4. `Referral`: El `server` devuelve una URL de otro `server` que puede tener más información sobre la solicitud, si corresponde.
5. `Response data`: El `server` devuelve cualquier dato adicional relacionado con la respuesta, como los atributos y valores de una entrada que fue buscada o modificada.

Después de recibir y procesar la respuesta, el `client` se desconecta del puerto LDAP.

### ldapsearch

Por ejemplo, `ldapsearch` es una utilidad de línea de comandos utilizada para buscar información almacenada en un `directory` utilizando el protocolo LDAP. Se utiliza comúnmente para consultar y recuperar datos de un `directory service` LDAP.

```r
ldapsearch -H ldap://ldap.example.com:389 -D "cn=admin,dc=example,dc=com" -w secret123 -b "ou=people,dc=example,dc=com" "(mail=john.doe@example.com)"

```
Este comando se puede desglosar de la siguiente manera:

- Conéctate al servidor `ldap.example.com` en el puerto `389`.
- Realiza la autenticación como `cn=admin,dc=example,dc=com` con la contraseña `secret123`.
- Busca bajo la base DN `ou=people,dc=example,dc=com`.
- Usa el filtro `(mail=john.doe@example.com)` para encontrar entradas que tengan esta dirección de correo electrónico.

El servidor procesaría la solicitud y enviaría una respuesta, que podría verse algo así:


```r
dn: uid=jdoe,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: John Doe
sn: Doe
uid: jdoe
mail: john.doe@example.com

result: 0 Success
```

Esta respuesta incluye el `distinguished name (DN)` de la entrada que coincide con los criterios de búsqueda y sus atributos y valores.

---

## LDAP Injection

`LDAP injection` es un ataque que explota aplicaciones web que usan `LDAP` (Lightweight Directory Access Protocol) para autenticación o almacenamiento de información de usuarios. El atacante puede inyectar código malicioso o caracteres en consultas LDAP para alterar el comportamiento de la aplicación, eludir medidas de seguridad y acceder a datos sensibles almacenados en el directorio LDAP.

Para probar `LDAP injection`, puedes usar valores de entrada que contengan caracteres especiales u operadores que puedan cambiar el significado de la consulta:

|Input|Descripción|
|---|---|
|`*`|Un asterisco `*` puede coincidir con cualquier número de caracteres.|
|`( )`|Los paréntesis `( )` pueden agrupar expresiones.|
|`\|`|Una barra vertical `\|` puede realizar una operación lógica OR.|
|`&`|Un ampersand `&` puede realizar una operación lógica AND.|
|`(cn=*)`|Valores de entrada que intentan eludir verificaciones de autenticación o autorización inyectando condiciones que siempre evalúan como verdaderas, como `(cn=*)` o `(objectClass=*)`, pueden ser usados en campos de nombre de usuario o contraseña.|

Los ataques de `LDAP injection` son similares a los ataques de `SQL injection` pero apuntan al servicio de directorio LDAP en lugar de una base de datos.

Por ejemplo, supongamos que una aplicación usa la siguiente consulta LDAP para autenticar usuarios:


```r
(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))
```

En esta consulta, `$username` y `$password` contienen las credenciales de inicio de sesión del usuario. Un atacante podría inyectar el carácter `*` en el campo `$username` o `$password` para modificar la consulta LDAP y eludir la autenticación.

Si un atacante inyecta el carácter `*` en el campo `$username`, la consulta LDAP coincidirá con cualquier cuenta de usuario con cualquier contraseña. Esto permitiría al atacante acceder a la aplicación con cualquier contraseña, como se muestra a continuación:


```r
$username = "*";
$password = "dummy";
(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))
```

Alternativamente, si un atacante inyecta el carácter `*` en el campo `$password`, la consulta LDAP coincidirá con cualquier cuenta de usuario con cualquier contraseña que contenga la cadena inyectada. Esto permitiría al atacante acceder a la aplicación con cualquier nombre de usuario, como se muestra a continuación:


```r
$username = "dummy";
$password = "*";
(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))
```

Los ataques de `LDAP injection` pueden tener consecuencias graves, como el acceso no autorizado a información sensible, la elevación de privilegios e incluso el control total sobre la aplicación o el servidor afectado. Estos ataques también pueden afectar considerablemente la integridad y disponibilidad de los datos, ya que los atacantes pueden alterar o eliminar datos dentro del servicio de directorio, causando interrupciones en las aplicaciones y servicios que dependen de esos datos.

Para mitigar los riesgos asociados con los ataques de `LDAP injection`, es crucial validar y sanitizar exhaustivamente las entradas del usuario antes de incorporarlas en consultas LDAP. Este proceso debe involucrar la eliminación de caracteres especiales específicos de LDAP, como `*`, y el uso de consultas parametrizadas para asegurar que las entradas del usuario se traten únicamente como datos y no como código ejecutable.

---

## Enumeration

La enumeración del objetivo nos ayuda a comprender los servicios y puertos expuestos. Un escaneo de servicios con `nmap` es una técnica de escaneo de red utilizada para identificar y analizar los servicios que se ejecutan en un sistema o red objetivo. Al sondear puertos abiertos y evaluar las respuestas, `nmap` puede deducir qué servicios están activos y sus respectivas versiones. El escaneo proporciona información valiosa sobre la infraestructura de red del objetivo, las posibles vulnerabilidades y las superficies de ataque.

### nmap

```r
nmap -p- -sC -sV --open --min-rate=1000 10.129.204.229

Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-23 14:43 SAST
Nmap scan report for 10.129.204.229
Host is up (0.18s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE VERSION
80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Login
389/tcp open  ldap    OpenLDAP 2.2.X - 2.3.X

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 149.73 seconds

```

`nmap` detecta un servidor `http` ejecutándose en el puerto `80` y un servidor `ldap` ejecutándose en el puerto `389`.

### Injection

Como `OpenLDAP` se ejecuta en el servidor, es seguro asumir que la aplicación web que se ejecuta en el puerto `80` utiliza LDAP para la autenticación.

Intentar iniciar sesión usando un carácter comodín (`*`) en los campos de nombre de usuario y contraseña permite el acceso al sistema, eludiendo efectivamente cualquier medida de autenticación que se haya implementado. Esto es un problema de seguridad significativo, ya que permite que cualquier persona con conocimiento de la vulnerabilidad obtenga acceso no autorizado al sistema y, potencialmente, a datos sensibles.