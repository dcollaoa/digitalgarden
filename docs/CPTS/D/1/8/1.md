El hardening (endurecimiento) adecuado de Linux puede eliminar la mayoría, si no todas, las oportunidades para la escalada de privilegios locales. Los siguientes pasos deben tomarse, como mínimo, para reducir el riesgo de que un ataque pueda elevarse a acceso de nivel root:

---

## Updates and Patching

Existen muchos exploits rápidos y fáciles de escalada de privilegios para kernels de Linux desactualizados y versiones vulnerables conocidas de servicios incorporados y de terceros. Realizar actualizaciones periódicas eliminará algunos de los "low hanging fruit" (frutos fáciles de alcanzar) que pueden aprovecharse para escalar privilegios. En Ubuntu, el paquete [unattended-upgrades](https://packages.ubuntu.com/jammy/admin/unattended-upgrades) está instalado por defecto desde la versión 18.04 y puede instalarse manualmente en Ubuntu desde al menos la versión 10.04 (Lucid). Los sistemas operativos basados en Debian desde antes de Jessie también tienen este paquete disponible. En sistemas basados en Red Hat, el paquete [yum-cron](https://man7.org/linux/man-pages/man8/yum-cron.8.html) realiza una tarea similar.

---

## Configuration Management

Esta no es una lista exhaustiva, pero algunas medidas de hardening simples son:

- Auditar archivos y directorios escribibles y cualquier binario configurado con el bit SUID.
- Asegurarse de que cualquier trabajo cron y privilegios sudo especifiquen cualquier binario usando la ruta absoluta.
- No almacenar credenciales en texto claro en archivos de lectura mundial.
- Limpiar los directorios home y el historial de bash.
- Asegurarse de que los usuarios de bajo privilegio no puedan modificar ninguna biblioteca personalizada llamada por programas.
- Eliminar cualquier paquete y servicio innecesario que potencialmente aumente la superficie de ataque.
- Considerar implementar [SELinux](https://www.redhat.com/en/topics/linux/what-is-selinux), que proporciona controles de acceso adicionales en el sistema.

---

## User Management

Debemos limitar la cantidad de cuentas de usuario y cuentas de administrador en cada sistema, asegurarnos de que los intentos de inicio de sesión (válidos/ inválidos) sean registrados y monitoreados. También es una buena idea aplicar una política de contraseñas fuertes, rotar contraseñas periódicamente y restringir a los usuarios de reutilizar contraseñas antiguas utilizando el archivo /etc/security/opasswd con el módulo PAM. Debemos verificar que los usuarios no estén colocados en grupos que les den derechos excesivos no necesarios para sus tareas diarias y limitar los derechos sudo basados en el principio de privilegio mínimo.

Existen plantillas para herramientas de automatización de gestión de configuración como [Puppet](https://puppet.com/use-cases/configuration-management/), [SaltStack](https://github.com/saltstack/salt), [Zabbix](https://en.wikipedia.org/wiki/Zabbix) y [Nagios](https://en.wikipedia.org/wiki/Nagios) para automatizar dichos controles y pueden usarse para enviar mensajes a un canal de Slack o una bandeja de correo electrónico, así como a través de otros métodos. Las acciones remotas (Zabbix) y las acciones de remediación (Nagios) pueden usarse para encontrar y corregir automáticamente estos problemas en una flota de nodos. Herramientas como Zabbix también cuentan con funciones como la verificación de checksums, que pueden usarse tanto para el control de versiones como para confirmar que los binarios sensibles no han sido manipulados. Por ejemplo, mediante el archivo [vfs.file.cksum](https://www.zabbix.com/documentation/4.0/manual/config/items/itemtypes/zabbix_agent).

---

## Audit

Realizar verificaciones periódicas de seguridad y configuración de todos los sistemas. Existen varias líneas base de seguridad como las [Security Technical Implementation Guides (STIGs)](https://public.cyber.mil/stigs/) de DISA que pueden seguirse para establecer un estándar de seguridad en todos los tipos de sistemas operativos y dispositivos. Existen muchos marcos de cumplimiento, como [ISO27001](https://www.iso.org/isoiec-27001-information-security.html), [PCI-DSS](https://www.pcisecuritystandards.org/pci_security/), y [HIPAA](https://www.hhs.gov/hipaa/for-professionals/security/index.html) que pueden ser utilizados por una organización para ayudar a establecer líneas base de seguridad. Todos estos deben ser utilizados como guías de referencia y no como la base de un programa de seguridad. Un programa de seguridad sólido debe tener controles adaptados a las necesidades de la organización, el entorno operativo y los tipos de datos que almacenan y procesan (es decir, información personal de salud, datos financieros, secretos comerciales o información de dominio público).

Una auditoría y revisión de configuración no es un reemplazo para una prueba de penetración u otros tipos de evaluaciones técnicas prácticas y a menudo se ve como un ejercicio de "marcar casillas" en el que una organización "aprueba" una auditoría de controles por realizar lo mínimo indispensable. Estas revisiones pueden ayudar a complementar los escaneos regulares de vulnerabilidades y pruebas de penetración, así como programas sólidos de gestión de parches, vulnerabilidades y configuración.

Una herramienta útil para auditar sistemas basados en Unix (Linux, macOS, BSD, etc.) es [Lynis](https://github.com/CISOfy/lynis). Esta herramienta audita la configuración actual de un sistema y proporciona consejos adicionales de hardening, teniendo en cuenta varios estándares. Puede ser utilizada por equipos internos como administradores de sistemas así como por terceros (auditores y pentesters) para obtener una "línea base" de la configuración de seguridad del sistema. Nuevamente, esta herramienta u otras similares no deben reemplazar las técnicas manuales discutidas en este módulo, pero pueden ser un fuerte complemento para cubrir áreas que pueden pasarse por alto.

Después de clonar el repositorio completo, podemos ejecutar la herramienta escribiendo `./lynis audit system` y recibir un informe completo.

```r
htb_student@NIX02:~$ ./lynis audit system

[ Lynis 3.0.1 ]

################################################################################
  Lynis comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
  welcome to redistribute it under the terms of the GNU General Public License.
  See the LICENSE file for details about using this software.

  2007-2020, CISOfy - https://cisofy.com/lynis/
  Enterprise support available (compliance, plugins, interface and tools)
################################################################################


[+] Initializing program
------------------------------------

  ###################################################################
  #                                                                 #
  #   NON-PRIVILEGED SCAN MODE                                      #
  #                                                                 #
  ###################################################################

  NOTES:
  --------------
  * Some tests will be skipped (as they require root permissions)
  * Some tests might fail silently or give different results

  - Detecting OS...                                           [ DONE ]
  - Checking profiles...                                      [ DONE ]

  ---------------------------------------------------
  Program version:           3.0.1
  Operating system:          Linux
  Operating system name:     Ubuntu
  Operating system version:  16.04
  Kernel version:            4.4.0
  Hardware platform:         x86_64
  Hostname:                  NIX02
```

El escaneo resultante se desglosará en advertencias:

```r
Warnings (2):
  ----------------------------
  ! Found one or more cronjob files with incorrect file permissions (see log for details) [SCHD-7704] 
      https://cisofy.com/lynis/controls/SCHD-7704/

  ! systemd-timesyncd never successfully synchronized time [TIME-3185] 
      https://cisofy.com/lynis/controls/TIME-3185/
```

Sugerencias:

```r
Suggestions (53):
  ----------------------------
  * Set a password on GRUB boot loader to prevent altering boot configuration (e.g. boot in single user mode without password) [BOOT-5122] 
      https://cisofy.com/lynis/controls/BOOT-5122/

  * If not required, consider explicit disabling of core dump in /etc/security/limits.conf file [KRNL-5820] 
      https://cisofy.com/lynis/controls/KRNL-5820/

  * Run pwck manually and correct any errors in the password file [AUTH-9228] 
      https://cisofy.com/lynis/controls/AUTH-9228/

  * Configure minimum encryption algorithm rounds in /etc/login.defs [AUTH-9230] 
      https://cisofy.com/lynis/controls/AUTH-9230/
```

y una sección de detalles generales del escaneo:

```r
Lynis security scan details:

  Hardening index : 60 [############        ]
  Tests performed : 256
  Plugins enabled : 2

  Components:
  - Firewall               [X]
  - Malware scanner        [X]

  Scan mode:
  Normal [ ]  Forensics [ ]  Integration [ ]  Pentest [V] (running non-privileged)

  Lynis modules:
  - Compliance status      [?]
  - Security audit         [V]
  - Vulnerability scan     [V]

  Files:
  - Test and debug information      : /home/mrb3n/lynis.log
  - Report data                     : /home/mrb3n/lynis-report.dat
```

La herramienta es útil para informar caminos de escalada de privilegios y realizar una verificación rápida de configuración, y realizará aún más verificaciones si se ejecuta como usuario root.

---

## Conclusion

Como hemos visto, hay varias formas de escalar privilegios en sistemas Linux/Unix: desde simples configuraciones incorrectas y exploits públicos para servicios vulnerables conocidos hasta el desarrollo de exploits basados en bibliotecas personalizadas. Una vez obtenido el acceso root, se vuelve más fácil usarlo como punto de pivote para una mayor explotación de la red. El hardening de Linux (y de todos los sistemas) es crucial para organizaciones de todos los tamaños. Existen directrices y controles de mejores prácticas en muchas formas diferentes. Las revisiones deben incluir una mezcla de pruebas manuales prácticas y revisión, y escaneo y validación automatizados de la configuración y los resultados.
