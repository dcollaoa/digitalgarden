Después de obtener acceso inicial (foothold), elevar nuestros privilegios nos brindará más opciones para la persistencia y puede revelar información almacenada localmente que puede aumentar nuestro acceso dentro del entorno. El objetivo general de la elevación de privilegios en Windows es aumentar nuestro acceso a un sistema dado a un miembro del grupo `Local Administrators` o la cuenta `NT AUTHORITY\SYSTEM` [LocalSystem](https://docs.microsoft.com/en-us/windows/win32/services/localsystem-account). Sin embargo, puede haber escenarios donde escalar a otro usuario en el sistema sea suficiente para alcanzar nuestro objetivo. La elevación de privilegios es típicamente un paso vital durante cualquier engagement. Necesitamos usar el acceso obtenido, o algunos datos (como credenciales) que solo se encuentran una vez que tenemos una sesión en un contexto elevado. En algunos casos, la elevación de privilegios puede ser el objetivo final de la evaluación si nuestro cliente nos contrata para una evaluación tipo "gold image" o "workstation breakout". La elevación de privilegios es a menudo vital para continuar a través de una red hacia nuestro objetivo final, así como para el movimiento lateral.

Dicho esto, puede que necesitemos escalar privilegios por una de las siguientes razones:

| #  | Uso                                                                                                              |
|----|------------------------------------------------------------------------------------------------------------------|
| 1. | Cuando se prueba una [gold image](https://www.techopedia.com/definition/29456/golden-image) de la estación de trabajo y la construcción del servidor Windows de un cliente en busca de fallas                                         |
| 2. | Para escalar privilegios localmente y obtener acceso a algún recurso local, como una base de datos                                                      |
| 3. | Para obtener acceso a nivel de [NT AUTHORITY\System](https://docs.microsoft.com/en-us/windows/win32/services/localsystem-account) en una máquina unida a un dominio para obtener acceso a la red de Active Directory del cliente     |
| 4. | Para obtener credenciales para moverse lateralmente o escalar privilegios dentro de la red del cliente                                                  |

Hay muchas herramientas disponibles para nosotros como penetration testers para ayudar con la elevación de privilegios. Sin embargo, también es esencial comprender cómo realizar verificaciones de elevación de privilegios y aprovechar las fallas `manualmente` en la medida de lo posible en un escenario dado. Podemos encontrarnos en situaciones donde un cliente nos coloca en una estación de trabajo gestionada sin acceso a Internet, con un firewall fuerte y puertos USB deshabilitados, por lo que no podemos cargar herramientas/scripts auxiliares. En este caso, sería crucial tener un firme conocimiento de las verificaciones de elevación de privilegios en Windows utilizando tanto PowerShell como la línea de comandos de Windows.

Los sistemas Windows presentan una amplia superficie de ataque. Solo algunas de las formas en que podemos escalar privilegios son:

| Técnica                                    | Descripción                                    |
|--------------------------------------------|-----------------------------------------------|
| Abusar de privilegios de grupo de Windows  | Abusar de privilegios de usuario de Windows    |
| Eludir el User Account Control             | Abusar de permisos de servicio/archivo débiles |
| Aprovechar exploits de kernel no parcheados| Robo de credenciales                           |
| Captura de tráfico                         | y más.                                         |

---

## Scenario 1 - Overcoming Network Restrictions

Una vez se me asignó la tarea de escalar privilegios en un sistema proporcionado por un cliente sin acceso a Internet y con los puertos USB bloqueados. Debido al control de acceso a la red en su lugar, no pude conectar mi máquina de ataque directamente a la red del usuario para asistirme. Durante la evaluación, ya había encontrado una falla en la red en la que la VLAN de la impresora estaba configurada para permitir la comunicación saliente sobre los puertos 80, 443 y 445. Utilicé métodos de enumeración manual para encontrar una falla relacionada con permisos que me permitió escalar privilegios y realizar un volcado manual de memoria del proceso `LSASS`. Desde aquí, pude montar un recurso compartido SMB alojado en mi máquina de ataque en la VLAN de la impresora y extraer el archivo `LSASS` DMP. Con este archivo en mano, utilicé `Mimikatz` sin conexión para recuperar el hash de la contraseña NTLM para un administrador de dominio, que pude descifrar sin conexión y usar para acceder a un controlador de dominio desde el sistema proporcionado por el cliente.

---

## Scenario 2 - Pillaging Open Shares

Durante otra evaluación, me encontré en un entorno bastante cerrado que estaba bien monitoreado y sin fallas de configuración obvias o servicios/aplicaciones vulnerables en uso. Encontré un recurso compartido de archivos completamente abierto, que permitía a todos los usuarios listar sus contenidos y descargar archivos almacenados en él. Este recurso compartido estaba alojando copias de seguridad de máquinas virtuales en el entorno. Me interesaron específicamente los archivos de discos duros virtuales (`.VMDK` y `.VHDX`). Pude acceder a este recurso compartido desde una máquina virtual de Windows, montar el disco duro virtual `.VHDX` como una unidad local y navegar por el sistema de archivos. Desde aquí, recuperé los hives del registro `SYSTEM`, `SAM` y `SECURITY`, los moví a mi caja de ataque Linux y extraje el hash de la contraseña del administrador local usando la herramienta [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py). La organización usaba una gold image, y el hash del administrador local se podía usar para obtener acceso de administrador a casi todos los sistemas Windows mediante un ataque de pass-the-hash.

---

## Scenario 3 - Hunting Credentials and Abusing Account Privileges

En este último escenario, me colocaron en una red bastante cerrada con el objetivo de acceder a servidores de bases de datos críticos. El cliente me proporcionó una laptop con una cuenta de usuario de dominio estándar y pude cargar herramientas en ella. Eventualmente, ejecuté la herramienta [Snaffler](https://github.com/SnaffCon/Snaffler) para buscar información sensible en recursos compartidos de archivos. Encontré algunos archivos `.sql` que contenían credenciales de base de datos de bajo privilegio para una base de datos en uno de sus servidores de bases de datos. Utilicé un cliente MSSQL localmente para conectarme a la base de datos usando las credenciales de la base de datos, habilitar el procedimiento almacenado [xp_cmdshell](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver15) y obtener ejecución de comandos local. Usando este acceso como una cuenta de servicio, confirmé que tenía el [SeImpersonatePrivilege](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/seimpersonateprivilege-secreateglobalprivilege), que se puede aprovechar para la elevación de privilegios locales. Descargué una versión compilada personalizada de [Juicy Potato](https://github.com/ohpe/juicy-potato) en el host para ayudar con la elevación de privilegios, y pude agregar un usuario administrador local. Agregar un usuario no era ideal, pero mis intentos de obtener un beacon/reverse shell no funcionaron. Con este acceso, pude conectarme remotamente al host de la base de datos y obtener control completo de una de las bases de datos de los clientes de la compañía.

---

## Why does Privilege Escalation Happen?

No hay una sola razón por la cual el host de una empresa puede ser víctima de una elevación de privilegios, pero existen varias posibles causas subyacentes. Algunas razones típicas por las que se introducen fallas y pasan desapercibidas son el personal y el presupuesto. Muchas organizaciones simplemente no tienen el personal adecuado para mantener al día con los parches, la gestión de vulnerabilidades, evaluaciones internas periódicas (autoevaluaciones), monitoreo continuo e iniciativas más grandes y más intensivas en recursos. Tales iniciativas pueden incluir actualizaciones de estaciones de trabajo y servidores, así como auditorías de recursos compartidos de archivos (para bloquear directorios y asegurar/eliminar archivos sensibles como scripts o archivos de configuración que contengan credenciales).

---

## Moving On

Los escenarios anteriores muestran cómo un entendimiento de la elevación de privilegios en Windows es crucial para un penetration tester. En el mundo real, rara vez estaremos atacando un solo host y necesitamos ser capaces de pensar rápidamente. Debemos ser capaces de encontrar formas creativas para escalar privilegios y formas de usar este acceso para avanzar hacia el objetivo de la evaluación.

---

## Practical Examples

A lo largo del módulo, cubriremos ejemplos con salida de comandos acompañante, la mayoría de los cuales se pueden reproducir en las máquinas virtuales objetivo que se pueden generar dentro de las secciones relevantes. Se le proporcionarán credenciales RDP para interactuar con las máquinas virtuales objetivo y completar los ejercicios de la sección y las evaluaciones de habilidades. Puede conectarse desde el Pwnbox o su propia máquina virtual (después de descargar una clave VPN una vez que se genera una máquina) a través de RDP usando [FreeRDP](https://github.com/FreeRDP/FreeRDP/wiki/CommandLineInterface), [Remmina](https://remmina.org/) o el cliente RDP de su elección.

### Connecting via FreeRDP

Podemos conectarnos a través de la línea de comandos usando el comando `xfreerdp /v:<target ip> /u:htb-student` y escribiendo la contraseña proporcionada cuando se le solicite. La mayoría de las secciones proporcionarán credenciales para el usuario `htb-student`, pero algunas, dependiendo del material, le harán conectarse a través de RDP con un usuario diferente, y se proporcionarán credenciales alternativas.

```r
 xfreerdp /v:10.129.43.36 /u:htb-student

[21:17:27:323] [28158:28159] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[21:17:27:323] [28158:28159] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[21:17:27:324] [28158:28159] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[21:17:27:324] [28158:28159] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
[21:17:27:648] [28158:28159] [INFO][com.freerdp.primitives] - primitives autodetect, using optimized
[21:17:27:672] [28158:28159] [INFO][com.freerdp.core] - freerdp_tcp_is_hostname_resolvable:freerdp_set_last_error_ex resetting error state
[21:17:27:672] [28158:28159] [INFO][com.freerdp.core] - freerdp_tcp_connect:freerdp_set_last_error_ex resetting error state
[21:17:28:770] [28158:28159] [INFO][com.freerdp.crypto] - creating directory /home/user2/.config/freerdp
[21:17:28:770] [28158:28159] [INFO][com.freerdp.crypto] - creating directory [/home/user2/.config/freerdp/certs]
[21:17:28:771] [28158:28159] [INFO][com.freerdp.crypto] - created directory [/home/user2/.config/freerdp/server]
[21:17:28:794] [28158:28159] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[21:17:28:794] [28158:28159] [WARN][com.freerdp.crypto] - CN = WINLPE-SKILLS1-SRV
[21:17:28:795] [28158:28159] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:17:28:795] [28158:28159] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[21:17:28:795] [28158:28159] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:17:28:795] [28158:28159] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.43.36:3389) 
[21:17:28:795] [28158:28159] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[21:17:28:795] [28158:28159] [ERROR][com.freerdp.crypto] - Common Name (CN):
[21:17:28:795] [28158:28159] [ERROR][com.freerdp.crypto] - 	WINLPE-SKILLS1-SRV
[21:17:28:795] [28158:28159] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.43.36:3389 (RDP-Server):
	Common Name: WINLPE-SKILLS1-SRV
	Subject:     CN = WINLPE-SKILLS1-SRV
	Issuer:      CN = WINLPE-SKILLS1-SRV
	Thumbprint:  9f:f0:dd:28:f5:6f:83:db:5e:8c:5a:e9:5f:50:a4:50:2d:b3:e7:a7:af:f4:4a:8a:1a:08:f3:cb:46:c3:c3:e8
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) y
Password: 
```

Muchas de las secciones del módulo requieren herramientas como scripts de código abierto, binarios precompilados y PoCs de exploits. Donde sea aplicable, estos se pueden encontrar en el directorio `C:\Tools` en el host objetivo. Aunque se proporcionan la mayoría de las herramientas, desafíate a ti mismo para cargar archivos en el objetivo (usando técnicas mostradas en el módulo de [File Transfers](https://academy.hackthebox.com/course/preview/file-transfers)) e incluso compilar algunas de las herramientas por tu cuenta utilizando [Visual Studio](https://visualstudio.microsoft.com/downloads/).

¡Diviértete y no olvides pensar fuera de la caja!

-mrb3n