Es común que tanto usuarios como administradores dejen las configuraciones predeterminadas. Los administradores deben hacer seguimiento de toda la tecnología, infraestructura y aplicaciones, junto con los datos que se están accediendo. En este caso, `the same password` se utiliza a menudo con fines de configuración y luego se olvida cambiar la contraseña para una interfaz u otra. Además, muchas aplicaciones que trabajan con mecanismos de autenticación, básicamente casi todas, vienen con `default credentials` después de la instalación. Estas credenciales predeterminadas pueden olvidarse de cambiarse después de la configuración, especialmente cuando se trata de aplicaciones internas donde los administradores asumen que nadie más las encontrará y ni siquiera intentan usarlas.

Además, se suelen usar contraseñas fáciles de recordar y que se pueden teclear rápidamente en lugar de contraseñas de 15 caracteres de longitud, porque [Single-Sign-On](https://en.wikipedia.org/wiki/Single_sign-on) (`SSO`) no siempre está disponible inmediatamente durante la instalación inicial, y la configuración en redes internas requiere cambios significativos. Al configurar redes, a veces trabajamos con infraestructuras extensas (dependiendo del tamaño de la empresa) que pueden tener muchos cientos de interfaces. A menudo se pasa por alto un dispositivo de red, como un router, impresora o firewall, y se utilizan las `default credentials` o se reutiliza la misma `password`.

---

## Credential Stuffing

Existen diversas bases de datos que mantienen una lista actualizada de credenciales predeterminadas conocidas. Una de ellas es la [DefaultCreds-Cheat-Sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet). Aquí hay un pequeño extracto de la tabla completa de esta hoja de trucos:

| **Product/Vendor** | **Username** | **Password** |
|--------------------|-------------|--------------|
| Zyxel (ssh)        | zyfwp       | PrOw!aN_fXp  |
| APC UPS (web)      | apc         | apc          |
| Weblogic (web)     | system      | manager      |
| ...                | ...         | ...          |

Las credenciales predeterminadas también se pueden encontrar en la documentación del producto, ya que contienen los pasos necesarios para configurar el servicio con éxito. Algunos dispositivos/aplicaciones requieren que el usuario establezca una contraseña al instalar, pero otros utilizan una contraseña predeterminada y débil. Atacar esos servicios con las credenciales predeterminadas o obtenidas se llama [Credential Stuffing](https://owasp.org/www-community/attacks/Credential_stuffing). Esta es una variante simplificada del brute-forcing porque solo se utilizan nombres de usuario compuestos y las contraseñas asociadas.

Podemos imaginar que hemos encontrado algunas aplicaciones utilizadas en la red por nuestros clientes. Después de buscar en internet las credenciales predeterminadas, podemos crear una nueva lista que separe estas credenciales compuestas con dos puntos (`username:password`). Además, podemos seleccionar las contraseñas y mutarlas según nuestras `rules` para aumentar la probabilidad de aciertos.

### Credential Stuffing - Hydra Syntax

```r
hydra -C <user_pass.list> <protocol>://<IP>
```

### Credential Stuffing - Hydra

```r
hydra -C user_pass.list ssh://10.129.42.197

...
```

Aquí, OSINT juega otro papel significativo. Porque OSINT nos da una "idea" de cómo está estructurada la empresa y su infraestructura, entenderemos qué contraseñas y nombres de usuario podemos combinar. Luego podemos almacenar estos en nuestras listas y usarlos posteriormente. Además, podemos usar Google para ver si las aplicaciones que encontramos tienen credenciales codificadas que se pueden usar.

### Google Search - Default Credentials

  
![](https://academy.hackthebox.com/storage/modules/147/Google-default-creds.png)

Además de las credenciales predeterminadas para aplicaciones, algunas listas las ofrecen para routers. Una de estas listas se puede encontrar [aquí](https://www.softwaretestinghelp.com/default-router-username-and-password-list/). Es mucho menos probable que las credenciales predeterminadas para los routers se dejen sin cambios. Dado que estos son las interfaces centrales para las redes, los administradores suelen prestar mucha más atención a su fortalecimiento. Sin embargo, todavía es posible que se pase por alto un router o que actualmente solo se esté utilizando en la red interna con fines de prueba, lo que luego podemos explotar para realizar más ataques.

| **Product/Vendor** | **Username** | **Password** |
|--------------------|-------------|--------------|
| Zyxel (ssh)        | zyfwp       | PrOw!aN_fXp  |
| APC UPS (web)      | apc         | apc          |
| Weblogic (web)     | system      | manager      |
| Weblogic (web)     | system      | manager      |
| Weblogic (web)     | weblogic    | weblogic1    |
| Weblogic (web)     | WEBLOGIC    | WEBLOGIC     |
| Weblogic (web)     | PUBLIC      | PUBLIC       |
| Weblogic (web)     | EXAMPLES    | EXAMPLES     |
| Weblogic (web)     | weblogic    | weblogic     |
| Weblogic (web)     | system      | password     |
| Weblogic (web)     | weblogic    | welcome(1)   |
| Weblogic (web)     | system      | welcome(1)   |
| Weblogic (web)     | operator    | weblogic     |
| Weblogic (web)     | operator    | password     |
| Weblogic (web)     | system      | Passw0rd     |
| Weblogic (web)     | monitor     | password     |
| Kanboard (web)     | admin       | admin        |
| Vectr (web)        | admin       | 11_ThisIsTheFirstPassword_11 |
| Caldera (web)      | admin       | admin        |
| Dlink (web)        | admin       | admin        |
| Dlink (web)        | 1234        | 1234         |
| Dlink (web)        | root        | 12345        |
| Dlink (web)        | root        | root         |
| JioFiber           | admin       | jiocentrum   |
| GigaFiber          | admin       | jiocentrum   |
| Kali linux (OS)    | kali        | kali         |
| F5                 | admin       | admin        |
| F5                 | root        | default      |
| F5                 | support     |              |
|...|...|...|
