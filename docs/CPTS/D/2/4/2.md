Supongamos que los eventos de [auditing of process creation](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation) y los valores correspondientes de la línea de comandos están habilitados. En ese caso, esta información se guarda en el log de eventos de seguridad de Windows como el ID de evento [4688: A new process has been created](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688). Las organizaciones pueden habilitar el registro de líneas de comando de procesos para ayudar a los defensores a monitorear e identificar comportamientos posiblemente maliciosos e identificar binarios que no deberían estar presentes en un sistema. Estos datos se pueden enviar a una herramienta SIEM o ingerir en una herramienta de búsqueda, como ElasticSearch, para dar visibilidad a los defensores sobre qué binarios se están ejecutando en los sistemas de la red. Las herramientas luego marcarían cualquier actividad potencialmente maliciosa, como los comandos `whoami`, `netstat` y `tasklist` ejecutados desde la workstation de un ejecutivo de marketing.

Este [study](https://blogs.jpcert.or.jp/en/2016/01/windows-commands-abused-by-attackers.html) muestra algunos de los comandos más ejecutados por atacantes después del acceso inicial (`tasklist`, `ver`, `ipconfig`, `systeminfo`, etc.), para reconocimiento (`dir`, `net view`, `ping`, `net use`, `type`, etc.), y para propagar malware dentro de una red (`at`, `reg`, `wmic`, `wusa`, etc.). Además de monitorear estos comandos, una organización podría llevar las cosas un paso más allá y restringir la ejecución de comandos específicos utilizando reglas de AppLocker ajustadas. Para una organización con un presupuesto de seguridad limitado, aprovechar estas herramientas integradas de Microsoft puede ofrecer una excelente visibilidad de las actividades de la red a nivel de host. La mayoría de las herramientas EDR empresariales modernas realizan detección/bloqueo, pero pueden estar fuera del alcance de muchas organizaciones debido a restricciones presupuestarias y de personal. Este pequeño ejemplo muestra que las mejoras de seguridad, como la visibilidad a nivel de red y host, se pueden lograr con un esfuerzo mínimo, costo y un impacto masivo.

Realicé una prueba de penetración contra una organización de tamaño medio hace unos años con un pequeño equipo de seguridad, sin EDR empresarial, pero que usaba una configuración similar a la detallada anteriormente (auditing de process creation y valores de la línea de comandos). Capturaron y contuvieron a uno de los miembros de mi equipo cuando ejecutó el comando `tasklist` desde la workstation de un miembro del departamento de finanzas (después de capturar credenciales usando `Responder` y craquearlas offline).

Los administradores o miembros del grupo [Event Log Readers](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255(v=ws.11)?redirectedfrom=MSDN#event-log-readers) tienen permiso para acceder a este log. Es posible que los administradores de sistemas quieran agregar usuarios avanzados o desarrolladores a este grupo para realizar ciertas tareas sin tener que otorgarles acceso administrativo.

### Confirming Group Membership

```r
C:\htb> net localgroup "Event Log Readers"

Alias name   
Comment        Members of this group can read event logs from local machine

Members

-------------------------------------------------------------------------------
logger
The command completed successfully.
```

Microsoft ha publicado una referencia [guide](https://download.microsoft.com/download/5/8/9/58911986-D4AD-4695-BF63-F734CD4DF8F2/ws-commands.pdf) para todos los comandos integrados de Windows, incluidos sintaxis, parámetros y ejemplos. Muchos comandos de Windows admiten pasar una contraseña como parámetro, y si el auditing de las líneas de comando de los procesos está habilitado, esta información sensible se capturará.

Podemos consultar eventos de Windows desde la línea de comandos utilizando la utilidad [wevtutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil) y el cmdlet de PowerShell [Get-WinEvent](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.1).

### Searching Security Logs Using wevtutil

```r
PS C:\htb> wevtutil qe Security /rd:true /f:text | Select-String "/user"

        Process Command Line:   net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```

También podemos especificar credenciales alternativas para `wevtutil` utilizando los parámetros `/u` y `/p`.

### Passing Credentials to wevtutil

```r
C:\htb> wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
```

Para `Get-WinEvent`, la sintaxis es la siguiente. En este ejemplo, filtramos los eventos de creación de procesos (4688), que contienen `/user` en la línea de comandos del proceso.

Nota: La búsqueda en el log de eventos `Security` con `Get-WInEvent` requiere acceso de administrador o permisos ajustados en la clave del registro `HKLM\System\CurrentControlSet\Services\Eventlog\Security`. La membresía solo en el grupo `Event Log Readers` no es suficiente.

### Searching Security Logs Using Get-WinEvent

```r
PS C:\htb> Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}

CommandLine
-----------
net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```

El cmdlet también se puede ejecutar como otro usuario con el parámetro `-Credential`.

Otros logs incluyen el [PowerShell Operational](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.1) log, que también puede contener información sensible o credenciales si el registro de bloques de script o módulos está habilitado. Este log es accesible para usuarios sin privilegios.