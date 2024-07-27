Durante nuestras pruebas de penetración, cada red de computadoras que encontramos tendrá servicios instalados para gestionar, editar o crear contenido. Todos estos servicios se alojan utilizando permisos específicos y se asignan a usuarios específicos. Aparte de las aplicaciones web, estos servicios incluyen (pero no se limitan a):

| FTP       | SMB   | NFS         |
| --------- | ----- | ----------- |
| IMAP/POP3 | SSH   | MySQL/MSSQL |
| RDP       | WinRM | VNC         |
| Telnet    | SMTP  | LDAP        |

Para más información sobre muchos de estos servicios, consulta el módulo [Footprinting](https://academy.hackthebox.com/course/preview/footprinting) en HTB Academy.

Imaginemos que queremos gestionar un servidor Windows a través de la red. En consecuencia, necesitamos un servicio que nos permita acceder al sistema, ejecutar comandos en él o acceder a sus contenidos a través de una GUI o terminal. En este caso, los servicios más comunes adecuados para esto son `RDP`, `WinRM` y `SSH`. SSH ahora es mucho menos común en Windows, pero es el servicio principal para sistemas basados en Linux.

Todos estos servicios tienen un mecanismo de autenticación utilizando un nombre de usuario y contraseña. Por supuesto, estos servicios pueden ser modificados y configurados para que solo se puedan usar claves predefinidas para iniciar sesión, pero muchos casos están configurados con ajustes predeterminados.

---

## WinRM

[Windows Remote Management](https://docs.microsoft.com/en-us/windows/win32/winrm/portal) (`WinRM`) es la implementación de Microsoft del protocolo de red [Web Services Management Protocol](https://docs.microsoft.com/en-us/windows/win32/winrm/ws-management-protocol) (`WS-Management`). Es un protocolo de red basado en servicios web XML utilizando el [Simple Object Access Protocol](https://docs.microsoft.com/en-us/windows/win32/winrm/windows-remote-management-glossary) (`SOAP`) usado para la gestión remota de sistemas Windows. Se encarga de la comunicación entre [Web-Based Enterprise Management](https://en.wikipedia.org/wiki/Web-Based_Enterprise_Management) (`WBEM`) y la [Windows Management Instrumentation](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page) (`WMI`), que puede llamar al [Distributed Component Object Model](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/4a893f3d-bd29-48cd-9f43-d9777a4415b0) (`DCOM`).

Sin embargo, por razones de seguridad, WinRM debe ser activado y configurado manualmente en Windows 10. Por lo tanto, depende mucho de la seguridad del entorno en un dominio o red local donde queramos usar WinRM. En la mayoría de los casos, se utilizan certificados o solo mecanismos de autenticación específicos para aumentar su seguridad. WinRM utiliza los puertos TCP `5985` (`HTTP`) y `5986` (`HTTPS`).

Una herramienta útil que podemos usar para nuestros ataques de contraseña es [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec), que también se puede usar para otros protocolos como SMB, LDAP, MSSQL, entre otros. Recomendamos leer la [documentación oficial](https://web.archive.org/web/20231116172005/https://www.crackmapexec.wiki/) para familiarizarte con ella.

### CrackMapExec

### Installing CrackMapExec

Podemos instalar `CrackMapExec` mediante apt en un host Parrot o clonar el [repositorio de GitHub](https://github.com/byt3bl33d3r/CrackMapExec) y seguir los diversos métodos de [instalación](https://github.com/byt3bl33d3r/CrackMapExec/wiki/Installation), como instalar desde la fuente y evitar problemas de dependencia.

```r
sudo apt-get -y install crackmapexec
```

### CrackMapExec Menu Options

Ejecutar la herramienta con la flag `-h` nos mostrará instrucciones generales de uso y algunas opciones disponibles para nosotros.

```r
crackmapexec -h
```

### CrackMapExec Protocol-Specific Help

Nota que podemos especificar un protocolo específico y recibir un menú de ayuda más detallado con todas las opciones disponibles para nosotros. CrackMapExec actualmente soporta autenticación remota usando MSSQL, SMB, SSH y WinRM.

```r
crackmapexec smb -h
```

### CrackMapExec Usage

El formato general para usar CrackMapExec es el siguiente:

```r
crackmapexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>
```

```r
crackmapexec winrm 10.129.42.197 -u user.list -p password.list
```

La aparición de `(Pwn3d!)` es la señal de que lo más probable es que podamos ejecutar comandos del sistema si iniciamos sesión con el usuario forzado. Otra herramienta útil que podemos usar para comunicarnos con el servicio WinRM es [Evil-WinRM](https://github.com/Hackplayers/evil-winrm), que nos permite comunicarnos con el servicio WinRM de manera eficiente.

### Evil-WinRM

### Installing Evil-WinRM

```r
sudo gem install evil-winrm
```

### Evil-WinRM Usage

```r
evil-winrm -i <target-IP> -u <username> -p <password>
```

```r
evil-winrm -i 10.129.42.197 -u user -p password
```

Si el inicio de sesión fue exitoso, se inicia una sesión de terminal usando el [Powershell Remoting Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/602ee78e-9a19-45ad-90fa-bb132b7cecec) (`MS-PSRP`), que simplifica la operación y ejecución de comandos.

---

## SSH

[Secure Shell](https://www.ssh.com/academy/ssh/protocol) (`SSH`) es una forma más segura de conectar a un host remoto para ejecutar comandos del sistema o transferir archivos de un host a un servidor. El servidor SSH funciona en el `TCP port 22` por defecto, al cual podemos conectar usando un cliente SSH. Este servicio utiliza tres diferentes operaciones/métodos de criptografía: `symmetric` encryption, `asymmetric` encryption, y `hashing`.

### Symmetric Encryption

La encriptación simétrica utiliza la `same key` para encriptar y desencriptar. Sin embargo, cualquiera que tenga acceso a la clave también podría acceder a los datos transmitidos. Por lo tanto, se necesita un procedimiento de intercambio de claves para la encriptación simétrica segura. El método de intercambio de claves [Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) se utiliza para este propósito. Si un tercero obtiene la clave, no puede descifrar los mensajes porque el método de intercambio de claves es desconocido. Sin embargo, esto es utilizado por el servidor y el cliente para determinar la clave secreta necesaria para acceder a los datos. Se pueden usar muchas variantes diferentes del sistema de cifrado simétrico, como AES, Blowfish, 3DES, etc.

### Asymmetrical Encryption

La encriptación asimétrica utiliza `two SSH keys`: una clave privada y una clave pública. La clave privada debe permanecer en secreto porque solo ella puede descifrar los mensajes que han sido encriptados con la clave pública. Si un atacante obtiene la clave privada, que a menudo no está protegida por contraseña, podrá iniciar sesión en el sistema sin credenciales. Una vez que se establece una conexión, el servidor utiliza la clave pública para la inicialización y autenticación. Si el cliente puede descifrar el mensaje, tiene la clave privada, y la sesión SSH puede comenzar.

### Hashing

El método de hashing convierte los datos transmitidos en otro valor único. SSH utiliza hashing para confirmar la autenticidad de los mensajes. Este es un algoritmo matemático que solo funciona en una dirección.

### Hydra - SSH

Podemos usar una herramienta como `Hydra` para forzar bruscamente SSH. Esto se cubre en profundidad en el módulo [Login Brute Forcing](https://academy.hackthebox.com/course/preview/login-brute-forcing/introduction-to-brute-forcing).

```r
hydra -L user.list -P password.list ssh://10.129.42.197
```

Para iniciar sesión en el sistema a través del protocolo SSH, podemos usar el cliente OpenSSH, que está disponible de manera predeterminada en la mayoría de las distribuciones Linux.



```r
ssh user@10.129.42.197
```

---

## Remote Desktop Protocol (RDP)

El [Remote Desktop Protocol](https://docs.microsoft.com/en-us/troubleshoot/windows-server/remote/understanding-remote-desktop-protocol) (`RDP`) de Microsoft es un protocolo de red que permite el acceso remoto a sistemas Windows a través del `TCP port 3389` por defecto. RDP proporciona tanto a los usuarios como al personal de soporte/administradores acceso remoto a hosts Windows dentro de una organización. El Remote Desktop Protocol define dos participantes para una conexión: un llamado servidor terminal, en el cual se realiza el trabajo real, y un cliente terminal, mediante el cual se controla de forma remota el servidor terminal. Además del intercambio de imagen, sonido, teclado y dispositivo de señalización, el RDP también puede imprimir documentos del servidor terminal en una impresora conectada al cliente terminal o permitir el acceso a medios de almacenamiento disponibles allí. Técnicamente, el RDP es un protocolo de capa de aplicación en la pila IP y puede usar TCP y UDP para la transmisión de datos. El protocolo es utilizado por varias aplicaciones oficiales de Microsoft, pero también es utilizado en algunas soluciones de terceros.

### Hydra - RDP

También podemos usar `Hydra` para realizar fuerza bruta en RDP.

```r
hydra -L user.list -P password.list rdp://10.129.42.197
```

Linux ofrece diferentes clientes para comunicarse con el servidor deseado usando el protocolo RDP. Estos incluyen [Remmina](https://remmina.org/), [rdesktop](http://www.rdesktop.org/), [xfreerdp](https://linux.die.net/man/1/xfreerdp), y muchos otros. Para nuestros propósitos, trabajaremos con xfreerdp.

### xFreeRDP

```r
xfreerdp /v:<target-IP> /u:<username> /p:<password>
```

![](https://academy.hackthebox.com/storage/modules/147/RDP.png)

---

## SMB

[Server Message Block](https://docs.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview) (`SMB`) es un protocolo responsable de transferir datos entre un cliente y un servidor en redes de área local. Se utiliza para implementar servicios de compartición de archivos y directorios e impresión en redes Windows. SMB a menudo se conoce como un sistema de archivos, pero no lo es. SMB puede compararse con `NFS` para Unix y Linux para proporcionar unidades en redes locales.

SMB también se conoce como [Common Internet File System](https://cifs.com/) (`CIFS`). Es parte del protocolo SMB y permite la conexión remota universal de múltiples plataformas como Windows, Linux o macOS. Además, a menudo encontraremos [Samba](https://wiki.samba.org/index.php/Main_Page), que es una implementación de código abierto de las funciones mencionadas. Para SMB, también podemos usar `hydra` nuevamente para probar diferentes nombres de usuario en combinación con diferentes contraseñas.

### Hydra - SMB

```r
hydra -L user.list -P password.list smb://10.129.42.197
```

Sin embargo, también podemos obtener el siguiente error que describe que el servidor ha enviado una respuesta inválida.

### Hydra - Error

```r
hydra -L user.list -P password.list smb://10.129.42.197
```

Esto se debe a que muy probablemente tenemos una versión desactualizada de THC-Hydra que no puede manejar las respuestas de SMBv3. Para solucionar este problema, podemos actualizar y recompilar `hydra` manualmente o usar otra herramienta muy poderosa, el [Metasploit framework](https://www.metasploit.com/).

### Metasploit Framework

```r
msfconsole -q
```

Ahora podemos usar `CrackMapExec` nuevamente para ver las comparticiones disponibles y qué privilegios tenemos para ellas.

### CrackMapExec

```r
crackmapexec smb 10.129.42.197 -u "user" -p "password" --shares
```

Para comunicarnos con el servidor a través de SMB, podemos usar, por ejemplo, la herramienta [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html). Esta herramienta nos permitirá ver los contenidos de las comparticiones, subir o descargar archivos si nuestros privilegios lo permiten.

### Smbclient

```r
smbclient -U user \\\\10.129.42.197\\SHARENAME
```

**`Nota:`** Para completar las preguntas del desafío, asegúrate de descargar las listas de palabras proporcionadas en los Recursos en la parte superior de la página.