While this module primarily focuses on modern operating systems (Windows 10/Windows Server 2016), as we have seen, certain issues (i.e., vulnerable software, misconfigurations, careless users, etc.) cannot be solved by merely upgrading to the latest and greatest Windows desktop and server versions. Dicho esto, se han realizado mejoras específicas de seguridad a lo largo de los años que ya no afectan a las versiones modernas y compatibles del sistema operativo (operating system) Windows. Durante nuestras evaluaciones, sin duda encontraremos sistemas operativos (operating systems) antiguos (especialmente contra grandes organizaciones como universidades, hospitales/organizaciones médicas, compañías de seguros, servicios públicos, gobiernos estatales/municipales). Es esencial comprender las diferencias y ciertos fallos adicionales que debemos verificar para garantizar que nuestras evaluaciones sean lo más exhaustivas posible.

---

## End of Life Systems (EOL)

Con el tiempo, Microsoft decide dejar de ofrecer soporte continuo para versiones específicas del sistema operativo (operating system). Cuando dejan de soportar una versión de Windows, dejan de lanzar actualizaciones de seguridad para la versión en cuestión. Los sistemas Windows primero entran en un período de "soporte extendido" antes de ser clasificados como fin de vida o ya no oficialmente soportados. Microsoft continúa creando actualizaciones de seguridad para estos sistemas ofrecidos a grandes organizaciones a través de contratos personalizados de soporte a largo plazo. A continuación, se muestra una lista de versiones populares de Windows y sus fechas de fin de vida:

### Windows Desktop - EOL Dates by Version

|Version|Date|
|---|---|
|Windows XP|April 8, 2014|
|Windows Vista|April 11, 2017|
|Windows 7|January 14, 2020|
|Windows 8|January 12, 2016|
|Windows 8.1|January 10, 2023|
|Windows 10 release 1507|May 9, 2017|
|Windows 10 release 1703|October 9, 2018|
|Windows 10 release 1809|November 10, 2020|
|Windows 10 release 1903|December 8, 2020|
|Windows 10 release 1909|May 11, 2021|
|Windows 10 release 2004|December 14, 2021|
|Windows 10 release 20H2|May 10, 2022|

### Windows Server - EOL Dates by Version

|Version|Date|
|---|---|
|Windows Server 2003|April 8, 2014|
|Windows Server 2003 R2|July 14, 2015|
|Windows Server 2008|January 14, 2020|
|Windows Server 2008 R2|January 14, 2020|
|Windows Server 2012|October 10, 2023|
|Windows Server 2012 R2|October 10, 2023|
|Windows Server 2016|January 12, 2027|
|Windows Server 2019|January 9, 2029|

This [page](https://michaelspice.net/windows/end-of-life-microsoft-windows-and-office/) has a more detailed listing of the end-of-life dates for Microsoft Windows and other products such as Exchange, SQL Server, and Microsoft Office, all of which we may run into during our assessments.

---

## Impact

Cuando los sistemas operativos (operating systems) llegan al final de su vida útil (end of life) y ya no son oficialmente soportados, pueden presentarse muchos problemas:

|Issue|Description|
|---|---|
|Lack of support from software companies|Certain applications (such as web browsers and other essential applications) may cease to work once a version of Windows is no longer officially supported.|
|Hardware issues|Newer hardware components will likely stop working on legacy systems.|
|Security flaws|This is the big one with a few notable exceptions (such as [CVE-2020-1350](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-1350) (SIGRed) o EternalBlue ([CVE-2017-0144](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2017-0144))) which were easily exploitable and "wormable" security flaws which affected thousands of systems worldwide (including critical infrastructure such as hospitals). Microsoft will no longer release security updates for end-of-life systems. This could leave the systems open to remote code execution and privilege escalation flaws that will remain unpatched until the system is upgraded or retired.|

En algunos casos, es difícil o imposible para una organización actualizar o retirar un sistema en fin de vida (end of life) debido a restricciones de costos y personal. El sistema puede estar ejecutando software crítico para la misión que ya no es soportado por el proveedor original. Esto es común en entornos médicos y gobiernos locales, donde el proveedor de una aplicación crítica sale del negocio o deja de proporcionar soporte para una aplicación, por lo que la organización se ve obligada a ejecutarla en una versión de Windows XP o incluso Server 2000/2003. Si descubrimos esto durante una evaluación, es mejor discutirlo con el cliente para comprender las razones comerciales por las que no pueden actualizar o retirar el/los sistema(s) y sugerir soluciones como la segmentación estricta de la red para aislar estos sistemas hasta que puedan ser tratados adecuadamente.

Como penetration testers, a menudo nos encontraremos con sistemas operativos (operating systems) antiguos. Aunque no veo muchos hosts ejecutando Server 2000 o estaciones de trabajo Windows XP vulnerables a [MS08-067](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067), existen, y los encuentro ocasionalmente. Es más común ver algunos hosts Server 2003 y 2008. Cuando encontramos estos sistemas, a menudo son vulnerables a una o múltiples fallas de ejecución remota de código o vectores de escalación de privilegios locales. Pueden ser una gran puerta de entrada al entorno. Sin embargo, al atacarlos, siempre debemos consultar con el cliente para asegurarnos de que no sean hosts frágiles que ejecutan aplicaciones críticas para la misión que podrían causar una interrupción masiva. Hay varias protecciones de seguridad en las versiones más nuevas del sistema operativo (operating system) Windows que no existen en las versiones antiguas, lo que facilita mucho nuestras tareas de escalación de privilegios.

Hay algunas diferencias notables entre las versiones antiguas y nuevas de las versiones del sistema operativo (operating system) Windows. Si bien este módulo tiene como objetivo enseñar técnicas de escalación de privilegios locales que se pueden usar contra versiones modernas de OS (operating system) Windows, sería negligente no repasar algunas de las diferencias clave entre las versiones más comunes. El núcleo del módulo se centra en varias versiones de Windows 10, Server 2016 y 2019, pero hagamos un viaje por el pasado y analicemos tanto un sistema Windows 7 como uno Server 2008 desde la perspectiva de un penetration tester con el objetivo de identificar diferencias clave que son cruciales durante las evaluaciones de grandes entornos.