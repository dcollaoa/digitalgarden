Las aplicaciones thick client son aquellas que se instalan localmente en nuestros computadores. A diferencia de las aplicaciones thin client, que se ejecutan en un servidor remoto y se pueden acceder a través del navegador web, estas aplicaciones no requieren acceso a internet para funcionar y tienen mejor rendimiento en términos de capacidad de procesamiento, memoria y almacenamiento. Las aplicaciones thick client suelen ser utilizadas en entornos empresariales y creadas para propósitos específicos. Entre estas aplicaciones se incluyen sistemas de gestión de proyectos, sistemas de gestión de relaciones con clientes, herramientas de gestión de inventarios y otro software de productividad. Estas aplicaciones suelen desarrollarse utilizando Java, C++, .NET o Microsoft Silverlight.

Una medida de seguridad crítica que, por ejemplo, Java tiene es una tecnología llamada sandbox. La sandbox es un entorno virtual que permite que el código no confiable, como el código descargado de internet, se ejecute de manera segura en el sistema del usuario sin representar un riesgo de seguridad. Además, aísla el código no confiable, impidiendo que acceda o modifique los recursos del sistema y otras aplicaciones sin la debida autorización. Además de eso, también existen las Java API restrictions y Code Signing que ayudan a crear un entorno más seguro.

En un entorno .NET, un thick client, también conocido como rich client o fat client, se refiere a una aplicación que realiza una cantidad significativa de procesamiento en el lado del cliente en lugar de depender únicamente del servidor para todas las tareas de procesamiento. Como resultado, los thick clients pueden ofrecer un mejor rendimiento, más características y experiencias de usuario mejoradas en comparación con sus contrapartes thin client, que dependen en gran medida del servidor para el procesamiento y almacenamiento de datos.

Algunos ejemplos de aplicaciones thick client son navegadores web, reproductores de medios, software de chat y videojuegos. Algunas aplicaciones thick client suelen estar disponibles para su compra o descarga gratuita a través de su sitio web oficial o tiendas de aplicaciones de terceros, mientras que otras aplicaciones personalizadas que han sido creadas para una empresa específica, pueden ser entregadas directamente por el departamento de IT que ha desarrollado el software. Implementar y mantener aplicaciones thick client puede ser más difícil que las aplicaciones thin client, ya que los parches y actualizaciones deben hacerse localmente en el computador del usuario. Algunas características de las aplicaciones thick client son:

- Software independiente.
- Funcionamiento sin acceso a internet.
- Almacenamiento de datos localmente.
- Menos seguro.
- Consumo de más recursos.
- Más caro.

Las aplicaciones thick client se pueden categorizar en arquitectura de dos niveles y de tres niveles. En la arquitectura de dos niveles, la aplicación se instala localmente en el computador y se comunica directamente con la base de datos. En la arquitectura de tres niveles, las aplicaciones también se instalan localmente en el computador, pero para interactuar con las bases de datos, primero se comunican con un servidor de aplicaciones, generalmente utilizando el protocolo HTTP/HTTPS. En este caso, el servidor de aplicaciones y la base de datos pueden estar ubicados en la misma red o a través de internet. Esto hace que la arquitectura de tres niveles sea más segura, ya que los atacantes no podrán comunicarse directamente con la base de datos. La siguiente imagen muestra las diferencias entre las aplicaciones de arquitectura de dos niveles y tres niveles.

![arch_tiers](https://academy.hackthebox.com/storage/modules/113/thick_clients/arch_tiers.png)

Dado que una gran parte de las aplicaciones thick client se descargan de internet, no hay una forma suficiente de asegurar que los usuarios descarguen la aplicación oficial, lo que genera preocupaciones de seguridad. Las vulnerabilidades específicas de la web como XSS, CSRF y Clickjacking no se aplican a las aplicaciones thick client. Sin embargo, las aplicaciones thick client se consideran menos seguras que las aplicaciones web, con muchos ataques aplicables, incluyendo:

- Manejo incorrecto de errores.
- Datos sensibles hardcoded.
- DLL Hijacking.
- Buffer Overflow.
- SQL Injection.
- Almacenamiento inseguro.
- Gestión de sesiones.

---

## Penetration Testing Steps

Las aplicaciones thick client se consideran más complejas que otras, y la superficie de ataque puede ser grande. El penetration testing de aplicaciones thick client se puede realizar tanto usando herramientas automatizadas como manualmente. Los siguientes pasos se suelen seguir al probar aplicaciones thick client.

### Information Gathering

En este paso, los penetration testers deben identificar la arquitectura de la aplicación, los lenguajes de programación y frameworks que se han utilizado, y entender cómo funcionan la aplicación y la infraestructura. También deben identificar las tecnologías que se utilizan en los lados del cliente y del servidor y encontrar puntos de entrada e inputs de usuario. Los testers también deben buscar identificar vulnerabilidades comunes como las que mencionamos anteriormente al final de la sección [About](https://academy.hackthebox.com/module/113/section/2139##About). Las siguientes herramientas nos ayudarán a recopilar información.

| [CFF Explorer](https://ntcore.com/?page_id=388) | [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) | [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) | [Strings](https://learn.microsoft.com/en-us/sysinternals/downloads/strings) |
| ----------------------------------------------- | ----------------------------------------------------------- | ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |

### Client Side attacks

Aunque los thick clients realizan un procesamiento y almacenamiento de datos significativos en el lado del cliente, todavía se comunican con servidores para varias tareas, como la sincronización de datos o el acceso a recursos compartidos. Esta interacción con servidores y otros sistemas externos puede exponer a los thick clients a vulnerabilidades similares a las que se encuentran en las aplicaciones web, incluyendo command injection, weak access control y SQL injection.

Información sensible como nombres de usuario y contraseñas, tokens o strings para la comunicación con otros servicios, pueden estar almacenados en los archivos locales de la aplicación. Credenciales hardcoded y otra información sensible también se pueden encontrar en el código fuente de la aplicación, por lo que el análisis estático es un paso necesario mientras se prueba la aplicación. Usando las herramientas adecuadas, podemos hacer ingeniería inversa y examinar aplicaciones .NET y Java, incluidos formatos de archivos como EXE, DLL, JAR, CLASS, WAR, entre otros. También se debe realizar análisis dinámico en este paso, ya que las aplicaciones thick client almacenan información sensible en la memoria también.

| [Ghidra](https://www.ghidra-sre.org/)   | [IDA](https://hex-rays.com/ida-pro/) | [OllyDbg](http://www.ollydbg.de/)      | [Radare2](https://www.radare.org/r/index.html) |
| --------------------------------------- | ------------------------------------ | -------------------------------------- | ---------------------------------------------- |
| [dnSpy](https://github.com/dnSpy/dnSpy) | [x64dbg](https://x64dbg.com/)        | [JADX](https://github.com/skylot/jadx) | [Frida](https://frida.re/)                     |

### Network Side Attacks

Si la aplicación se está comunicando con un servidor local o remoto, el análisis del tráfico de red nos ayudará a capturar información sensible que podría estar siendo transferida a través de conexiones HTTP/HTTPS o TCP/UDP, y nos dará una mejor comprensión de cómo funciona esa aplicación. Los penetration testers que realicen análisis de tráfico en aplicaciones thick client deben estar familiarizados con herramientas como:

[Wireshark](https://www.wireshark.org/) | [tcpdump](https://www.tcpdump.org/) | [TCPView](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview) | [Burp Suite](https://portswigger.net/burp)

### Server Side Attacks

Los ataques del lado del servidor en aplicaciones thick client son similares a los ataques de aplicaciones web, y los penetration testers deben prestar atención a los más comunes, incluyendo la mayoría de los OWASP Top Ten.

---

## Retrieving hardcoded Credentials from Thick-Client Applications

El siguiente escenario nos lleva a enumerar y explotar una aplicación thick client para movernos lateralmente dentro de una red corporativa durante un penetration testing. El escenario comienza después de haber obtenido acceso a un servicio SMB expuesto.

Explorar el share `NETLOGON` del servicio SMB revela `RestartOracle-Service.exe` entre otros archivos. Al descargar el ejecutable localmente y ejecutarlo a través de la línea de comandos, parece que no se ejecuta o ejecuta algo oculto.

```r
C:\Apps>.\Restart-OracleService.exe
C:\Apps>
```

Descargando la herramienta `ProcMon64` de [SysInternals](https://learn.microsoft.com/en-gb/sysinternals/downloads/procmon) y monitoreando el proceso revela que el ejecutable realmente crea un archivo temporal en `C:\Users\Matt\AppData\Local\Temp`.

![procmon](https://academy.hackthebox.com/storage/modules/113/thick_clients/procmon.png)

Para capturar los archivos, se requiere cambiar los permisos de la carpeta `Temp` para desactivar la eliminación de archivos. Para hacer esto, hacemos clic derecho en la carpeta `C:\Users\Matt\AppData\Local\Temp` y en `Properties` -> `Security` -> `Advanced` -> `cybervaca` -> `Disable inheritance` -> `Convert inherited permissions into explicit permissions on this object` -> `Edit` -> `Show advanced permissions`, deseleccionamos las casillas `Delete subfolders and files` y `Delete`.

![change-perms](https://academy.hackthebox.com/storage/modules/113/thick_clients/change-perms.png)

Finalmente, hacemos clic en `OK` -> `Apply` -> `OK` -> `OK` en las ventanas abiertas. Una vez aplicados los permisos de la carpeta, simplemente ejecut