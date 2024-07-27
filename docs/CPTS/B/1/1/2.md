Cada aplicación que soporta mecanismos de autenticación compara las entradas/credenciales proporcionadas con bases de datos locales o remotas. En el caso de las bases de datos locales, estas credenciales se almacenan localmente en el sistema. Las aplicaciones web a menudo son vulnerables a inyecciones SQL, lo que puede llevar al peor de los casos, donde los atacantes pueden ver la totalidad de los datos de una organización en texto plano.

Existen muchas listas de palabras que contienen las contraseñas más comúnmente utilizadas. Un ejemplo de una de estas listas es `rockyou.txt`. Esta lista incluye aproximadamente 14 millones de contraseñas únicas y fue creada después de una violación de datos de la empresa RockYou, que contenía un total de 32 millones de cuentas de usuario. La empresa RockYou almacenaba todas las credenciales en texto plano en su base de datos, lo cual los atacantes pudieron ver después de un ataque exitoso de inyección SQL.

También sabemos que cada sistema operativo soporta estos tipos de mecanismos de autenticación. Las credenciales almacenadas se almacenan localmente. Veamos cómo se crean, almacenan y gestionan estas credenciales en sistemas basados en Windows y Linux con más detalle.

---

## Linux

Como ya sabemos, los sistemas basados en Linux manejan todo en forma de archivo. En consecuencia, las contraseñas también se almacenan cifradas en un archivo. Este archivo se llama `shadow` y está ubicado en `/etc/shadow` y es parte del sistema de gestión de usuarios de Linux. Además, estas contraseñas se almacenan comúnmente en forma de `hashes`. Un ejemplo puede verse así:

### Shadow File

```r
root@htb:~# cat /etc/shadow

...SNIP...
htb-student:$y$j9T$3QSBB6CbHEu...SNIP...f8Ms:18955:0:99999:7:::
```

El archivo `/etc/shadow` tiene un formato único en el que las entradas se ingresan y guardan cuando se crean nuevos usuarios.

|               |                                   |                         |              |              |                     |                        |                      |                    |
| ------------- | --------------------------------- | ----------------------- | ------------ | ------------ | ------------------- | ---------------------- | -------------------- | ------------------ |
| htb-student:  | $y$j9T$3QSBB6CbHEu...SNIP...f8Ms: | 18955:                  | 0:           | 99999:       | 7:                  | :                      | :                    | :                  |
| `<username>`: | `<encrypted password>`:           | `<day of last change>`: | `<min age>`: | `<max age>`: | `<warning period>`: | `<inactivity period>`: | `<expiration date>`: | `<reserved field>` |

El cifrado de la contraseña en este archivo se formatea de la siguiente manera:

| `$ <id>` | `$ <salt>` | `$ <hashed>`                  |
| -------- | ---------- | ----------------------------- |
| `$ y`    | `$ j9T`    | `$ 3QSBB6CbHEu...SNIP...f8Ms` |

El tipo (`id`) es el método de hash criptográfico utilizado para cifrar la contraseña. Muchos métodos diferentes de hash criptográfico se usaron en el pasado y todavía se usan en algunos sistemas hoy en día.

|**ID**|**Cryptographic Hash Algorithm**|
|---|---|
|`$1$`|[MD5](https://en.wikipedia.org/wiki/MD5)|
|`$2a$`|[Blowfish](https://en.wikipedia.org/wiki/Blowfish_(cipher))|
|`$5$`|[SHA-256](https://en.wikipedia.org/wiki/SHA-2)|
|`$6$`|[SHA-512](https://en.wikipedia.org/wiki/SHA-2)|
|`$sha1$`|[SHA1crypt](https://en.wikipedia.org/wiki/SHA-1)|
|`$y$`|[Yescrypt](https://github.com/openwall/yescrypt)|
|`$gy$`|[Gost-yescrypt](https://www.openwall.com/lists/yescrypt/2019/06/30/1)|
|`$7$`|[Scrypt](https://en.wikipedia.org/wiki/Scrypt)|

Sin embargo, hay algunos archivos más que pertenecen al sistema de gestión de usuarios de Linux. Los otros dos archivos son `/etc/passwd` y `/etc/group`. En el pasado, la contraseña cifrada se almacenaba junto con el nombre de usuario en el archivo `/etc/passwd`, pero esto se reconoció cada vez más como un problema de seguridad porque el archivo puede ser visto por todos los usuarios en el sistema y debe ser legible. El archivo `/etc/shadow` solo puede ser leído por el usuario `root`.

### Passwd File

```r
cat /etc/passwd

...SNIP...
htb-student:x:1000:1000:,,,:/home/htb-student:/bin/bash
```

| `htb-student:` | `x:`          | `1000:`  | `1000:`  | `,,,:`       | `/home/htb-student:` | `/bin/bash`                       |
| -------------- | ------------- | -------- | -------- | ------------ | -------------------- | --------------------------------- |
| `<username>:`  | `<password>:` | `<uid>:` | `<gid>:` | `<comment>:` | `<home directory>:`  | `<cmd executed after logging in>` |

La `x` en el campo de contraseña indica que la contraseña cifrada está en el archivo `/etc/shadow`. Sin embargo, la redirección al archivo `/etc/shadow` no hace invulnerables a los usuarios en el sistema porque si los derechos de este archivo están configurados incorrectamente, el archivo puede ser manipulado para que el usuario `root` no necesite escribir una contraseña para iniciar sesión. Por lo tanto, un campo vacío significa que podemos iniciar sesión con el nombre de usuario sin ingresar una contraseña.

- [Linux User Auth](https://tldp.org/HOWTO/pdf/User-Authentication-HOWTO.pdf)

---

## Windows Authentication Process

El [Windows client authentication process](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication) puede ser muchas veces más complicado que en sistemas Linux y consiste en muchos módulos diferentes que realizan los procesos de inicio de sesión, recuperación y verificación completos. Además, hay muchos procedimientos de autenticación diferentes y complejos en el sistema Windows, como la autenticación Kerberos. La [Local Security Authority](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) (`LSA`) es un subsistema protegido que autentica a los usuarios e inicia sesión en la computadora local. Además, la LSA mantiene información sobre todos los aspectos de la seguridad local en una computadora. También proporciona varios servicios para traducir entre nombres e identificadores de seguridad (`SIDs`).

El subsistema de seguridad rastrea las políticas de seguridad y las cuentas que residen en un sistema informático. En el caso de un Domain Controller, estas políticas y cuentas se aplican al dominio donde se encuentra el Domain Controller. Estas políticas y cuentas se almacenan en Active Directory. Además, el subsistema LSA proporciona servicios para verificar el acceso a objetos, verificar los permisos de los usuarios y generar mensajes de monitoreo.

### Windows Authentication Process Diagram

![](https://academy.hackthebox.com/storage/modules/147/Auth_process1.png)

El inicio de sesión interactivo local se realiza mediante la interacción entre el proceso de inicio de sesión ([WinLogon](https://www.microsoftpressstore.com/articles/article.aspx?p=2228450&seqNum=8)), el proceso de interfaz de usuario de inicio de sesión (`LogonUI`), los `credential providers`, `LSASS`, uno o más `authentication packages` y `SAM` o `Active Directory`. Los paquetes de autenticación, en este caso, son las Dynamic-Link Libraries (`DLLs`) que realizan comprobaciones de autenticación. Por ejemplo, para inicios de sesión interactivos y no unidos al dominio, se utiliza el paquete de autenticación `Msv1_0.dll`.

`Winlogon` es un proceso confiable responsable de gestionar las interacciones de seguridad relacionadas con el usuario. Estos incluyen:

- Iniciar LogonUI para ingresar contraseñas al iniciar sesión
    
- Cambiar contraseñas
    
- Bloquear y desbloquear la estación de trabajo
    

Depende de los credential providers instalados en el sistema para obtener el nombre de cuenta o la contraseña de un usuario. Los credential providers son objetos `COM` que se encuentran en DLLs.

Winlogon es el único proceso que intercepta las solicitudes de inicio de sesión desde el teclado enviadas a través de un mensaje RPC desde Win32k.sys. Winlogon inicia inmediatamente la aplicación LogonUI al iniciar sesión para mostrar la interfaz de usuario para el inicio de sesión. Después de que Winlogon obtiene un nombre de usuario y una contraseña de los credential providers, llama a LSASS para autenticar al usuario que intenta iniciar sesión.

### LSASS

[Local Security Authority Subsystem Service](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service) (`LSASS`) es una colección de muchos módulos y tiene acceso a todos los procesos de autenticación que se pueden encontrar en `%SystemRoot%\System32\Lsass.exe`. Este servicio es responsable de la política de seguridad del sistema local, la autenticación de usuarios y el envío de registros de auditoría de seguridad al `Event log`.

 En otras palabras, es la bóveda para los sistemas operativos basados en Windows, y podemos encontrar una ilustración más detallada de la arquitectura de LSASS [aquí](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961760(v=technet.10)?redirectedfrom=MSDN).

|**Authentication Packages**|**Description**|
|---|---|
|`Lsasrv.dll`|El servicio LSA Server aplica las políticas de seguridad y actúa como el administrador de paquetes de seguridad para el LSA. El LSA contiene la función Negotiate, que selecciona el protocolo NTLM o Kerberos después de determinar qué protocolo será exitoso.|
|`Msv1_0.dll`|Paquete de autenticación para inicios de sesión en máquinas locales que no requieren autenticación personalizada.|
|`Samsrv.dll`|El Security Accounts Manager (SAM) almacena cuentas de seguridad locales, aplica políticas almacenadas localmente y admite APIs.|
|`Kerberos.dll`|Paquete de seguridad cargado por el LSA para autenticación basada en Kerberos en una máquina.|
|`Netlogon.dll`|Servicio de inicio de sesión basado en red.|
|`Ntdsa.dll`|Esta biblioteca se utiliza para crear nuevos registros y carpetas en el registro de Windows.|

Source: [Microsoft Docs](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication).

Cada sesión de inicio de sesión interactivo crea una instancia separada del servicio Winlogon. La [Graphical Identification and Authentication](https://docs.microsoft.com/en-us/windows/win32/secauthn/gina) (`GINA`) se carga en el área de proceso utilizada por Winlogon, recibe y procesa las credenciales, e invoca las interfaces de autenticación a través de la función [LSALogonUser](https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsalogonuser).

### SAM Database

El [Security Account Manager](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc756748(v=ws.10)?redirectedfrom=MSDN) (`SAM`) es un archivo de base de datos en los sistemas operativos Windows que almacena las contraseñas de los usuarios. Puede usarse para autenticar usuarios locales y remotos. SAM utiliza medidas criptográficas para evitar que usuarios no autenticados accedan al sistema. Las contraseñas de usuario se almacenan en un formato hash en una estructura de registro como un hash `LM` o un hash `NTLM`. Este archivo se encuentra en `%SystemRoot%/system32/config/SAM` y se monta en HKLM/SAM. Se requieren permisos de nivel SYSTEM para verlo.

Los sistemas Windows pueden asignarse a un grupo de trabajo o dominio durante la configuración. Si el sistema se ha asignado a un grupo de trabajo, maneja la base de datos SAM localmente y almacena todos los usuarios existentes localmente en esta base de datos. Sin embargo, si el sistema se ha unido a un dominio, el Domain Controller (`DC`) debe validar las credenciales desde la base de datos Active Directory (`ntds.dit`), que se almacena en `%SystemRoot%\ntds.dit`.

Microsoft introdujo una característica de seguridad en Windows NT 4.0 para ayudar a mejorar la seguridad de la base de datos SAM contra el cracking de software offline. Esta es la característica `SYSKEY` (`syskey.exe`), que, cuando está habilitada, cifra parcialmente la copia en disco duro del archivo SAM para que los valores hash de las contraseñas para todas las cuentas locales almacenadas en el SAM estén cifrados con una clave.

### Credential Manager

![](https://academy.hackthebox.com/storage/modules/147/authn_credman_credprov.png)

Source: [Microsoft Docs](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication).

Credential Manager es una característica incorporada en todos los sistemas operativos Windows que permite a los usuarios guardar las credenciales que utilizan para acceder a varios recursos de red y sitios web. Las credenciales guardadas se almacenan en función de los perfiles de usuario en el `Credential Locker` de cada usuario. Las credenciales están cifradas y se almacenan en la siguiente ubicación:

```r
PS C:\Users\[Username]\AppData\Local\Microsoft\[Vault/Credentials]\
```

Existen varios métodos para descifrar las credenciales guardadas utilizando Credential Manager. Practicaremos con algunos de estos métodos en este módulo.

### NTDS

Es muy común encontrarse con entornos de red donde los sistemas Windows están unidos a un dominio Windows. Esto es común porque facilita a los administradores gestionar todos los sistemas propiedad de sus respectivas organizaciones (gestión centralizada). En estos casos, los sistemas Windows enviarán todas las solicitudes de inicio de sesión a los Domain Controllers que pertenecen al mismo bosque de Active Directory. Cada Domain Controller aloja un archivo llamado `NTDS.dit` que se mantiene sincronizado en todos los Domain Controllers, con la excepción de los [Read-Only Domain Controllers](https://docs.microsoft.com/en-us/windows/win32/ad/rodc-and-active-directory-schema). NTDS.dit es un archivo de base de datos que almacena los datos en Active Directory, incluidos pero no limitados a:

- Cuentas de usuario (nombre de usuario y hash de contraseña)
- Cuentas de grupo
- Cuentas de computadora
- Objetos de política de grupo

Practicaremos métodos que nos permitan extraer credenciales del archivo NTDS.dit más adelante en este módulo.

Ahora que hemos repasado los conceptos de almacenamiento de credenciales, estudiemos los diversos ataques que podemos realizar para extraer credenciales y avanzar en nuestras evaluaciones.