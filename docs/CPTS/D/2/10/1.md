Proper hardening puede eliminar la mayoría, si no todas, las oportunidades de escalamiento de privilegios locales. Los siguientes pasos deben tomarse, como mínimo, para reducir el riesgo de que un atacante obtenga acceso a nivel de sistema.

---

## Secure Clean OS Installation

Tomarse el tiempo para desarrollar una imagen personalizada para tu entorno puede ahorrarte mucho tiempo en el futuro al solucionar problemas con los hosts. Puedes hacer esto utilizando una ISO limpia de la versión del OS que requieras, un servidor de Windows Deployment o una aplicación equivalente para empujar imágenes a través de medios de disco o networking, y System Center Configuration Manager (si es aplicable en tu entorno). SCCM y WDS son temas mucho más amplios de lo que tenemos espacio aquí, así que dejémoslo para otra ocasión. Puedes encontrar copias de Windows Operating Systems [aquí](https://www.microsoft.com/en-us/software-download/) o extraerlas usando la Microsoft Media Creation Tool. Esta imagen debería, como mínimo, incluir:

1. Cualquier aplicación requerida para las tareas diarias de tus empleados.
2. Cambios de configuración necesarios para asegurar la funcionalidad y seguridad del host en tu entorno.
3. Actualizaciones mayores y menores actuales ya probadas para tu entorno y consideradas seguras para el despliegue de hosts.

Al seguir este proceso, puedes asegurarte de eliminar cualquier bloatware o software no deseado preinstalado en el host en el momento de la compra. Esto también asegura que tus hosts en la empresa comiencen con la misma configuración base, permitiéndote solucionar problemas, hacer cambios y aplicar actualizaciones mucho más fácilmente.

---

## Updates and Patching

[Microsoft's Update Orchestrator](https://docs.microsoft.com/en-us/windows/deployment/update/how-windows-update-works) ejecutará actualizaciones por ti en segundo plano según tu configuración. Para la mayoría, esto significa que descargará e instalará las actualizaciones más recientes por ti detrás de escena. Ten en cuenta que algunas actualizaciones requieren un reinicio para tener efecto, por lo que es una buena práctica reiniciar tus hosts regularmente. Para aquellos que trabajan en un entorno empresarial, puedes configurar un servidor WSUS dentro de tu entorno para que cada computadora no tenga que descargarlas individualmente. En su lugar, pueden conectarse al servidor WSUS configurado para cualquier actualización requerida.

En resumen, el proceso de actualización se ve algo así:

![image](https://academy.hackthebox.com/storage/modules/67/Windows-Update-Process.png)

1. Windows Update Orchestrator se conectará con los servidores de Microsoft Update o tu propio servidor WSUS para encontrar nuevas actualizaciones necesarias.
    - Esto ocurrirá en intervalos aleatorios para que tus hosts no saturen el servidor de actualizaciones con solicitudes todas a la vez.
    - El Orchestrator luego verificará esa lista contra la configuración de tu host para extraer las actualizaciones apropiadas.
2. Una vez que el Orchestrator decida sobre las actualizaciones aplicables, iniciará las descargas en segundo plano.
    - Las actualizaciones se almacenan en la carpeta temp para su acceso. Se verifican los manifiestos de cada descarga y solo se extraen los archivos necesarios para aplicarlas.
3. Update Orchestrator luego llamará al agente de instalación y le pasará la lista de acciones necesarias.
4. Desde aquí, el agente de instalación aplica las actualizaciones.
    - Nota que las actualizaciones aún no están finalizadas.
5. Una vez que las actualizaciones están listas, Orchestrator las finalizará con un reinicio del host.
    - Esto asegura que cualquier modificación a los servicios o configuraciones críticas tenga efecto.

Estas acciones pueden ser gestionadas por [Windows Server Update Services](https://docs.microsoft.com/en-us/windows-server/administration/windows-server-update-services/get-started/windows-server-update-services-wsus), `WSUS` o a través de Group Policy. Independientemente del método elegido para aplicar actualizaciones, asegúrate de tener un plan en marcha y que las actualizaciones se apliquen regularmente para evitar cualquier problema que pueda surgir. Como en todo en el mundo IT, prueba primero la implementación de tus actualizaciones en un entorno de desarrollo (en unos pocos hosts) antes de implementarlas en toda la empresa. Esto asegurará que no rompas accidentalmente alguna aplicación o función crítica con las actualizaciones.

---

## Configuration Management

En Windows, la gestión de configuración puede lograrse fácilmente mediante el uso de Group Policy. Group Policy nos permitirá gestionar de forma centralizada la configuración y preferencias de usuarios y computadoras en tu entorno. Esto puede lograrse utilizando la Group Policy Management Console (GPMC) o a través de Powershell.

![image](https://academy.hackthebox.com/storage/modules/67/gpmc.png)

Group Policy funciona mejor en un entorno de Active Directory, pero también puedes gestionar la configuración de computadoras y usuarios locales a través de la política de grupo local. Desde aquí, puedes gestionar todo, desde los fondos de pantalla de los usuarios individuales, marcadores y otras configuraciones del navegador, hasta cómo y cuándo Windows Defender escanea el host y realiza actualizaciones. Este puede ser un proceso muy granular, así que asegúrate de tener un plan para la implementación de cualquier nueva política de grupo creada o modificada.

---

## User Management

Limitar la cantidad de cuentas de usuario y administrador en cada sistema y asegurar que los intentos de inicio de sesión (válidos/invalidos) sean registrados y monitoreados puede ser muy útil para el endurecimiento del sistema y monitoreo de problemas potenciales. También es bueno imponer una política de contraseñas fuertes y autenticación de dos factores, rotar contraseñas periódicamente y restringir a los usuarios para que no reutilicen contraseñas antiguas mediante el uso de los ajustes de `Password Policy` en Group Policy. Estos ajustes se pueden encontrar utilizando GPMC en la ruta `Computer Configuration\Windows Settings\Security Settings\Account Policies\Password Policy`. También deberíamos verificar que los usuarios no se coloquen en grupos que les otorguen derechos excesivos innecesarios para sus tareas diarias (por ejemplo, un usuario regular con derechos de Domain Admin) y hacer cumplir las restricciones de inicio de sesión para las cuentas de administrador.

![image](https://academy.hackthebox.com/storage/modules/67/password-policy.png)

Esta captura de pantalla muestra un ejemplo de cómo utilizar el editor de políticas de grupo para ver y modificar la política de contraseñas en la clave mencionada anteriormente.

Two Factor Authentication puede ayudar a prevenir inicios de sesión fraudulentos también. Una explicación rápida de 2FA es que requiere algo que sabes `contraseña o pin` y algo que tienes `un token, tarjeta de identificación o clave de aplicación de autenticación`. Este paso reducirá significativamente la capacidad de que las cuentas de usuario se utilicen maliciosamente.

---

## Audit

Realiza comprobaciones periódicas de seguridad y configuración de todos los sistemas. Existen varias bases de seguridad como los DISA [Security Technical Implementation Guides (STIGs)](https://public.cyber.mil/stigs/) o el [Security Compliance Toolkit](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/security-compliance-toolkit-10) de Microsoft que pueden seguirse para establecer un estándar de seguridad en tu entorno. Existen muchos marcos de cumplimiento, como [ISO27001](https://www.iso.org/isoiec-27001-information-security.html), [PCI-DSS](https://www.pcisecuritystandards.org/pci_security/), y [HIPAA](https://www.hhs.gov/hipaa/for-professionals/security/index.html) que pueden ser utilizados por una organización para ayudar a establecer bases de seguridad. Todos estos deberían usarse como guías de referencia y no como la base para un programa de seguridad. Un programa de seguridad sólido debe tener controles adaptados a las necesidades de la organización, el entorno operativo y los tipos de datos que almacenan y procesan (por ejemplo, información de salud personal, datos financieros, secretos comerciales o información disponible públicamente).

![image](https://academy.hackthebox.com/storage/modules/67/stig-viewer.png)

La ventana del STIG viewer que podemos ver arriba es una forma de realizar una auditoría de la postura de seguridad de un host. Importamos una lista de verificación encontrada en el enlace STIG anterior y revisamos las reglas. Cada ID de regla corresponde con una verificación de seguridad o tarea de endurecimiento para ayudar a mejorar la postura general del host. Al observar el panel derecho, puedes ver detalles sobre las acciones requeridas para completar la verificación STIG.

Una auditoría y revisión de configuración no es un reemplazo para una prueba de penetración u otros tipos de evaluaciones técnicas prácticas y a menudo se ven como un ejercicio de "marcar casillas" en el que una organización es "aprobada" en una auditoría de controles por realizar el mínimo indispensable. Estas revisiones pueden ayudar a complementar los escaneos de vulnerabilidades regulares, pruebas de penetración, y programas sólidos de gestión de parches, vulnerabilidades y configuraciones.

---

## Logging

El registro adecuado y la correlación de registros pueden marcar la diferencia al solucionar un problema o buscar una posible amenaza en tu red. A continuación, discutiremos algunas aplicaciones y registros que pueden ayudar a mejorar tu postura de seguridad en un host de Windows.

---

## Sysmon

Sysmon es una herramienta creada por Microsoft e incluida en el Sysinternals Suite que mejora la capacidad de registro y recopilación de eventos en Windows. Sysmon proporciona información detallada sobre cualquier proceso, conexiones de red, lecturas o escrituras de archivos, intentos de inicio de sesión y éxitos, y mucho más. Estos registros pueden correlacionarse y enviarse a un SIEM para su análisis y proporcionar una mejor comprensión de lo que sucede en tu entorno. Sysmon es persistente en el host y comenzará a escribir

 registros al inicio. Es una herramienta extremadamente útil si se implementa correctamente. Para obtener más detalles sobre Sysmon, consulta [sysmon info](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).

Cualquier registro que Sysmon escriba se almacenará en la clave: `Applications and Service Logs\Microsoft\Windows\Sysmon\Operational`. Puedes ver estos registros utilizando la aplicación de visor de eventos y profundizando en la clave.

---

## Network and Host Logs

Herramientas como [PacketBeat](https://www.elastic.co/beats/packetbeat), implementaciones de IDS\IPS como sensores de Security Onion y otras soluciones de monitoreo de red pueden ayudar a completar el panorama para tus administradores. Recopilan y envían registros de tráfico de red a tus soluciones de monitoreo y SIEMS.

---

## Key Hardening Measures

Esta no es una lista exhaustiva, pero algunas medidas simples de endurecimiento son:

- Secure boot y disk encryption con BitLocker deberían estar habilitados y en uso.
- Auditar archivos y directorios escribibles y cualquier binario con la capacidad de lanzar otras aplicaciones.
- Asegurarse de que cualquier tarea programada y scripts que se ejecuten con privilegios elevados especifiquen cualquier binario o ejecutable utilizando la ruta absoluta.
- No almacenar credenciales en texto claro en archivos de lectura mundial en el host o en unidades compartidas.
- Limpiar directorios de inicio y el historial de PowerShell.
- Asegurarse de que los usuarios con privilegios bajos no puedan modificar ninguna biblioteca personalizada llamada por programas.
- Eliminar cualquier paquete y servicio innecesario que potencialmente aumente la superficie de ataque.
- Utilizar las características de Device Guard y Credential Guard integradas por Microsoft en Windows 10 y la mayoría de los nuevos Server Operating Systems.
- Utilizar Group Policy para hacer cumplir cualquier cambio de configuración necesario en los sistemas de la empresa.

Podrías notar, si te tomas el tiempo de leer a través de una lista de verificación STIG, que muchas de estas medidas están incluidas en las verificaciones. Ten en cuenta lo que usan tus entornos y determina cómo estas medidas afectarán la capacidad de cumplir la misión. No implementes ciegamente medidas de endurecimiento generalizadas en tu red, ya que lo que funciona para una organización puede no funcionar para otra. Saber qué estás tratando de proteger y luego aplicar las medidas apropiadas según los requisitos del negocio es crítico.

---

## Conclusion

Como hemos visto, hay muchas formas diferentes de escalar privilegios en sistemas Windows, desde simples configuraciones incorrectas y exploits públicos para servicios conocidos vulnerables, hasta el desarrollo de exploits basados en bibliotecas y ejecutables personalizados. Una vez que se obtiene acceso de administrador o SYSTEM, se vuelve más fácil usarlo como un punto de pivote para una mayor explotación de la red. El endurecimiento del sistema es igualmente crítico para pequeñas empresas y grandes empresas. Al observar las tendencias de ataque de hoy en día, podemos ver que los atacantes ya no se preocupan por quién es la víctima, siempre y cuando puedan obtener lo que quieren del intercambio. Existen directrices y controles de mejores prácticas en muchas formas diferentes. Las revisiones deben incluir una mezcla de pruebas manuales prácticas y escaneos de configuración automatizados con herramientas como Nessus, seguidas de la validación de los resultados. Mientras parcheas para los ataques más recientes y sofisticados y implementas capacidades de monitoreo avanzadas, no olvides los conceptos básicos y los "frutos bajos" cubiertos a lo largo de este módulo.

Finalmente, asegúrate de que tu personal esté constantemente desafiado y capacitado y se mantenga a la vanguardia de nuevas vulnerabilidades y PoCs de exploits para que tu organización pueda permanecer protegida mientras los investigadores continúan descubriendo nuevas avenidas de ataque.