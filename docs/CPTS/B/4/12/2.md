Junto con la discusión sobre el hardening de un dominio AD, queríamos hablar sobre la `AD auditing`. Queremos proporcionar a nuestros clientes tanta información como sea posible para ayudar a resolver los problemas potenciales que encontremos. Hacer esto les dará más datos para probar que tienen un problema y ayudará a obtener respaldo y financiamiento para abordar esas soluciones. Las herramientas en esta sección se pueden utilizar para proporcionar diferentes visualizaciones y salida de datos para este propósito.

---

## Creating an AD Snapshot with Active Directory Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) es parte de la Sysinternal Suite y se describe como:

"Un visor y editor avanzado de Active Directory (AD). Puedes usar AD Explorer para navegar fácilmente por una base de datos de AD, definir ubicaciones favoritas, ver propiedades y atributos de objetos sin abrir cuadros de diálogo, editar permisos, ver el esquema de un objeto y ejecutar búsquedas sofisticadas que puedes guardar y volver a ejecutar."

AD Explorer también se puede usar para guardar snapshots de una base de datos de AD para su visualización y comparación offline. Podemos tomar un snapshot de AD en un momento dado y explorarlo más tarde, durante la fase de informe, como explorarías cualquier otra base de datos. También se puede usar para realizar una comparación antes y después de AD para descubrir cambios en objetos, atributos y permisos de seguridad.

Cuando cargamos la herramienta por primera vez, se nos pide credenciales de inicio de sesión o cargar un snapshot anterior. Podemos iniciar sesión con cualquier usuario de dominio válido.

### Logging in with AD Explorer

![image](https://academy.hackthebox.com/storage/modules/47/AD_explorer1.png)

Una vez iniciada la sesión, podemos navegar libremente por AD y ver información sobre todos los objetos.

### Browsing AD with AD Explorer

![image](https://academy.hackthebox.com/storage/modules/47/AD_explorer_logged_in.png)

Para tomar un snapshot de AD, vamos a File --> `Create Snapshot` e introducimos un nombre para el snapshot. Una vez completado, podemos moverlo offline para un análisis posterior.

### Creating a Snapshot of AD with AD Explorer

![image](https://academy.hackthebox.com/storage/modules/47/AD_explorer_snapshot.png)

---

## PingCastle

[PingCastle](https://www.pingcastle.com/documentation/) es una herramienta poderosa que evalúa la postura de seguridad de un entorno AD y nos proporciona los resultados en varios mapas y gráficos. Pensando en la seguridad por un segundo, si no tienes un inventario activo de los hosts en tu empresa, PingCastle puede ser un gran recurso para ayudarte a recopilar uno en un mapa del dominio legible para el usuario. PingCastle es diferente de herramientas como PowerView y BloodHound porque, además de proporcionarnos datos de enumeración que pueden informar nuestros ataques, también proporciona un informe detallado del nivel de seguridad del dominio objetivo utilizando una metodología basada en un marco de evaluación de riesgos/madurez. La puntuación mostrada en el informe se basa en el [Capability Maturity Model Integration](https://en.wikipedia.org/wiki/Capability_Maturity_Model_Integration) (CMMI). Para una vista rápida del contexto de ayuda proporcionado, puedes usar el flag `--help` en cmd-prompt.

Nota: Si tienes problemas para iniciar la herramienta, cambia la fecha del sistema a una fecha anterior al 31 de julio de 2023 usando el Panel de Control (Set the time and date).

### Viewing the PingCastle Help Menu

```r
C:\htb> PingCastle.exe --help

switch:
  --help              : display this message
  --interactive       : force the interactive mode
  --log               : generate a log file
  --log-console       : add log to the console
  --log-samba <option>: enable samba login (example: 10)

Common options when connecting to the AD
  --server <server>   : use this server (default: current domain controller)
                        the special value * or *.forest do the healthcheck for all domains
  --port <port>       : the port to use for ADWS or LDAP (default: 9389 or 389)
  --user <user>       : use this user (default: integrated authentication)
  --password <pass>   : use this password (default: asked on a secure prompt)
  --protocol <proto>  : selection the protocol to use among LDAP or ADWS (fastest)
                      : ADWSThenLDAP (default), ADWSOnly, LDAPOnly, LDAPThenADWS

<SNIP>  
```

### Running PingCastle

Para ejecutar PingCastle, podemos llamar al ejecutable escribiendo `PingCastle.exe` en nuestra ventana de CMD o PowerShell o haciendo clic en el ejecutable, y nos llevará al modo interactivo, presentándonos un menú de opciones dentro de la `Terminal User Interface` (`TUI`).

### PingCastle Interactive TUI

```r
|:.      PingCastle (Version 2.10.1.0     1/19/2022 8:12:02 AM)
|  #:.   Get Active Directory Security at 80% in 20% of the time
# @@  >  End of support: 7/31/2023
| @@@:
: .#                                 Vincent LE TOUX (contact@pingcastle.com)
  .:       twitter: @mysmartlogon                    https://www.pingcastle.com
What do you want to do?
=======================
Using interactive mode.
Do not forget that there are other command line switches like --help that you can use
  1-healthcheck-Score the risk of a domain
  2-conso      -Aggregate multiple reports into a single one
  3-carto      -Build a map of all interconnected domains
  4-scanner    -Perform specific security checks on workstations
  5-export     -Export users or computers
  6-advanced   -Open the advanced menu
  0-Exit
==============================
This is the main functionnality of PingCastle. In a matter of minutes, it produces a report which will give you an overview of your Active Directory security. This report can be generated on other domains by using the existing trust links.
```

La opción predeterminada es la ejecución `healthcheck`, que establecerá una visión general básica del dominio y nos proporcionará información pertinente sobre las misconfiguraciones y vulnerabilidades. Aún mejor, PingCastle puede informar sobre la susceptibilidad a vulnerabilidades recientes, nuestros shares, trusts, la delegación de permisos y mucho más sobre nuestros estados de usuarios y computadoras. Bajo la opción Scanner, podemos encontrar la mayoría de estas verificaciones.

### Scanner Options

```r
|:.      PingCastle (Version 2.10.1.0     1/19/2022 8:12:02 AM)
|  #:.   Get Active Directory Security at 80% in 20% of the time
# @@  >  End of support: 7/31/2023
| @@@:
: .#                                 Vincent LE TOUX (contact@pingcastle.com)
  .:       twitter: @mysmartlogon                    https://www.pingcastle.com
Select a scanner
================
What scanner whould you like to run ?
WARNING: Checking a lot of workstations may raise security alerts.
  1-aclcheck                                                  9-oxidbindings
  2-antivirus                                                 a-remote
  3-computerversion                                           b-share
  4-foreignusers                                              c-smb
  5-laps_bitlocker                                            d-smb3querynetwork
  6-localadmin                                                e-spooler
  7-nullsession                                               f-startup
  8-nullsession-trust                                         g-zerologon
  0-Exit
==============================
Check authorization related to users or groups. Default to everyone, authenticated users and domain users
```

Ahora que entendemos cómo funciona y cómo iniciar los escaneos, veamos el informe.

### Viewing The Report

A lo largo del informe, hay secciones como información del dominio, usuario, grupo y trust y una tabla específica que destaca "anomalías" o problemas que pueden requerir atención inmediata. También se nos presentará la puntuación de riesgo general del dominio.

![text](https://academy.hackthebox.com/storage/modules/143/report-example.png)

Además de ser útil para realizar una enumeración de dominio muy completa cuando se combina con otras herramientas, PingCastle puede ser útil para dar a los clientes un análisis rápido de su postura de seguridad del dominio, o puede ser utilizado por equipos internos para autoevaluarse y encontrar áreas de preocupación u oportunidades para un mayor hardening. Tómate un tiempo para explorar los informes y mapas que PingCastle puede generar en el dominio Inlanefreight.

### Group Policy

Con la group policy siendo una gran parte de cómo se maneja la administración de usuarios y computadoras de AD, es lógico que queramos auditar sus configuraciones y resaltar cualquier posible agujero. `Group3r` es una excelente herramienta para esto.

---

## Group3r

[Group3r](https://github.com/Group3r/Group3r) es una herramienta construida con el propósito de encontrar vulnerabilidades en la group policy asociada a Active Directory. Group3r debe ejecutarse desde un host unido a un dominio con un usuario de dominio (no necesita ser un administrador), o en el contexto de un usuario de dominio (es decir, usando `runas /netonly`).

### Group3r Basic Usage

```r
C:\htb> group3r.exe -f <filepath-name.log> 
```

Al ejecutar Group3r, debemos especificar el flag `-s` o el flag `-f`. Estos especificarán si enviar los resultados a stdout (-s) o al archivo al que queremos enviar los resultados (-f). Para más opciones e información de uso, utiliza el flag `-h` o consulta la información de uso en el enlace anterior.

A continuación se muestra un ejemplo de inicio de Group3r.

### Reading Output

![text](https://academy.hackthebox.com/storage/modules/143/grouper-output.png)

Al leer la salida de Group3r, cada sangría es un nivel diferente, por lo que ninguna sangría será el GPO, una sangría serán configuraciones de políticas y otra serán hallazgos en esas configuraciones. A continuación, veremos la salida mostrada de un hallazgo.

### Group3r Finding

![text](https://academy.hackthebox.com/storage/modules/143/grouper-finding.png)

En la imagen de arriba, verás un ejemplo de un hallazgo de Group3r. Se presentará como un cuadro vinculado a la configuración de la política, definirá la porción interesante y nos dará una razón para el hallazgo. Vale la pena el esfuerzo de ejecutar Group3r si tienes la oportunidad. A menudo encontrará caminos u objetos interesantes que otras herramientas pasarán por alto.

---

## ADRecon

Finalmente, hay varias otras herramientas útiles para recopilar una gran cantidad de datos de AD a la vez. En una evaluación donde no se requiere sigilo, también vale la pena ejecutar una herramienta como [ADRecon](https://github.com/adrecon/ADRecon) y analizar los resultados, en caso de que toda nuestra enumeración haya pasado por alto algo menor que pueda ser útil para nosotros o valga la pena señalar a nuestro cliente.

### Running ADRecon

```r
PS C:\htb> .\ADRecon.ps1

[*] ADRecon v1.1 by Prashant Mahajan (@prashant3535)
[*] Running on INLANEFREIGHT.LOCAL\MS01 - Member Server
[*] Commencing - 03/28/2022 09:24:58
[-] Domain
[-] Forest
[-] Trusts
[-] Sites
[-] Subnets
[-] SchemaHistory - May take some time
[-] Default Password Policy
[-] Fine Grained Password Policy - May need a Privileged Account
[-] Domain Controllers
[-] Users and SPNs - May take some time
[-] PasswordAttributes - Experimental
[-] Groups and Membership Changes - May take some time
[-] Group Memberships - May take some time
[-] OrganizationalUnits (OUs)
[-] GPOs
[-] gPLinks - Scope of Management (SOM)
[-] DNS Zones and Records
[-] Printers
[-] Computers and SPNs - May take some time
[-] LAPS - Needs Privileged Account
[-] BitLocker Recovery Keys - Needs Privileged Account
[-] GPOReport - May take some time
[*] Total Execution Time (mins): 11.05
[*] Output Directory: C:\Tools\ADRecon-Report-20220328092458
```

Una vez terminado, ADRecon dejará un informe para nosotros en una nueva carpeta bajo el directorio desde el que ejecutamos. Podemos ver un ejemplo de los resultados en la terminal a continuación. Obtendrás un informe en formato HTML y una carpeta con resultados en CSV. Al generar el informe, se debe tener en cuenta que el programa Excel debe estar instalado, o el script no generará automáticamente el informe de esa manera; solo te dejará con los archivos .csv. Si deseas salida para la group policy, debes asegurarte de que el host desde el que ejecutas tenga instalado el módulo de PowerShell `GroupPolicy`. Podemos volver más tarde y generar el informe de Excel desde otro host usando el flag `-GenExcel` y alimentando la carpeta del informe.

### Reporting

```r
PS C:\htb> ls

    Directory: C:\Tools\ADRecon-Report-20220328092458

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         3/28/2022  12:42 PM                CSV-Files
-a----         3/28/2022  12:42 PM        2758736 GPO-Report.html
-a----         3/28/2022  12:42 PM         392780 GPO-Report.xml
```

---

Hemos cubierto muchas herramientas y tácticas en este módulo, pero consideramos prudente mostrar y explicar algunas otras formas de auditar un dominio objetivo. Ten en cuenta que tus acciones deben servir a un propósito, y nuestro objetivo final es mejorar la postura de seguridad del cliente. Con eso en mente, adquirir más evidencia de problemas solo servirá para:

`Hacer nuestros informes más convincentes y proporcionar al cliente las herramientas que necesita para arreglar y asegurar activamente su dominio`.