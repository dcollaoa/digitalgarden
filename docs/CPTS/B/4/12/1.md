Tomemos un tiempo para ver algunas medidas de hardening que se pueden implementar para detener TTPs comunes como los que utilizamos en este módulo, evitando que sean exitosos o proporcionen información útil. Nuestro objetivo como penetration testers es ayudar a proporcionar una mejor visión operativa de la red de nuestros clientes a sus defensores y mejorar su postura de seguridad. Por lo tanto, debemos comprender algunas de las tácticas de defensa comunes que se pueden implementar y cómo afectarían a las redes que estamos evaluando. Estos pasos básicos de hardening harán mucho más por una organización (independientemente del tamaño) que comprar la próxima gran herramienta EDR o SIEM. Esas medidas y equipos defensivos adicionales solo ayudan si tienes una postura de seguridad base con características como el logging habilitado y la documentación adecuada y el seguimiento de los hosts dentro de la red.

## Step One: Document and Audit

Un adecuado hardening de Active Directory puede mantener a los atacantes contenidos y prevenir el lateral movement, privilege escalation y acceso a datos y recursos sensibles. Uno de los pasos esenciales en el hardening de Active Directory es comprender todo lo presente en tu entorno de Active Directory. Una auditoría de todo lo que se enumera a continuación debe realizarse anualmente, si no cada pocos meses, para garantizar que tus registros estén actualizados. Nos importa:

### Things To Document and Track

- `Naming conventions of OUs, computers, users, groups`
- `DNS, network, and DHCP configurations`
- `An intimate understanding of all GPOs and the objects that they are applied to`
- `Assignment of FSMO roles`
- `Full and current application inventory`
- `A list of all enterprise hosts and their location`
- `Any trust relationships we have with other domains or outside entities`
- `Users who have elevated permissions`

---

## People, Processes, and Technology

El hardening de Active Directory puede dividirse en las categorías _People_, _Process_ y _Technology_. Estas medidas de hardening abarcarán los aspectos de hardware, software y humanos de cualquier red.

### People

Incluso en el entorno más fortificado, los usuarios siguen siendo el eslabón más débil. Aplicar las mejores prácticas de seguridad para los usuarios estándar y administradores evitará "easy wins" para pentesters y atacantes maliciosos. También debemos esforzarnos por mantener a nuestros usuarios educados y conscientes de las amenazas. Las medidas a continuación son una excelente manera de comenzar a asegurar el elemento humano de un entorno de Active Directory.

- La organización debe tener una política de contraseñas sólida, con un filtro de contraseñas que no permita el uso de palabras comunes (es decir, welcome, password, nombres de meses/días/estaciones y el nombre de la empresa). Si es posible, se debe utilizar un password manager empresarial para ayudar a los usuarios a elegir y usar contraseñas complejas.
- Rotar periódicamente las contraseñas de **todas** las cuentas de servicio.
- Prohibir el acceso de administrador local en las estaciones de trabajo de los usuarios a menos que exista una necesidad comercial específica.
- Deshabilitar la cuenta `RID-500 local admin` predeterminada y crear una nueva cuenta de administrador para la administración sujeta a la rotación de contraseñas de LAPS.
- Implementar niveles divididos de administración para usuarios administrativos. Con demasiada frecuencia, durante una evaluación, obtendrás acceso a credenciales de Domain Administrator en una computadora que un administrador usa para todas las actividades laborales.
- Limpiar los grupos privilegiados. `¿La organización necesita más de 50 Domain/Enterprise Admins?` Restringir la membresía de grupos altamente privilegiados solo a aquellos usuarios que requieren este acceso para realizar sus tareas diarias de administración de sistemas.
- Cuando sea apropiado, colocar cuentas en el grupo `Protected Users`.
- Deshabilitar la delegación Kerberos para cuentas administrativas (el grupo Protected Users puede no hacer esto).

### Protected Users Group

El [Protected Users group](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) apareció por primera vez con Windows Server 2012 R2. Este grupo puede usarse para restringir lo que los miembros de este grupo privilegiado pueden hacer en un domain. Agregar usuarios a Protected Users evita que las credenciales de los usuarios sean abusadas si se dejan en la memoria en un host.

### Viewing the Protected Users Group with Get-ADGroup

```r
PS C:\Users\htb-student> Get-ADGroup -Identity "Protected Users" -Properties Name,Description,Members


Description       : Members of this group are afforded additional protections against authentication security threats.
                    See http://go.microsoft.com/fwlink/?LinkId=298939 for more information.
DistinguishedName : CN=Protected Users,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
GroupCategory     : Security
GroupScope        : Global
Members           : {CN=sqlprod,OU=Service Accounts,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL, CN=sqldev,OU=Service
                    Accounts,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL}
Name              : Protected Users
ObjectClass       : group
ObjectGUID        : e4e19353-d08f-4790-95bc-c544a38cd534
SamAccountName    : Protected Users
SID               : S-1-5-21-2974783224-3764228556-2640795941-525
```

El grupo proporciona las siguientes protecciones para el Domain Controller y el dispositivo:

- Los miembros del grupo no pueden ser delegados con delegación restringida o no restringida.
- CredSSP no almacenará en caché credenciales en texto plano en la memoria, incluso si Allow delegating default credentials está configurado en Group Policy.
- Windows Digest no almacenará en caché la contraseña en texto plano del usuario, incluso si Windows Digest está habilitado.
- Los miembros no pueden autenticarse usando NTLM authentication o usar claves DES o RC4.
- Después de adquirir un TGT, las claves a largo plazo del usuario o las credenciales en texto plano no se almacenarán en caché.
- Los miembros no pueden renovar un TGT por más tiempo que el TTL original de 4 horas.

Nota: El grupo Protected Users puede causar problemas imprevistos con la autenticación, lo que puede resultar fácilmente en bloqueos de cuentas. Una organización nunca debe colocar a todos los usuarios privilegiados en este grupo sin pruebas escalonadas.

Además de asegurarnos de que nuestros usuarios no puedan hacerse daño a sí mismos, debemos considerar nuestras políticas y procedimientos para el acceso y control del domain.

### Processes

Mantener y aplicar políticas y procedimientos que puedan impactar significativamente la postura de seguridad general de una organización es necesario. Sin políticas definidas, es imposible responsabilizar a los empleados de una organización y es difícil responder a un incidente sin procedimientos definidos y practicados, como un plan de recuperación ante desastres. Los elementos a continuación pueden ayudar a definir procesos, políticas y procedimientos.

- Políticas y procedimientos adecuados para la gestión de activos de Active Directory.
  - La auditoría de hosts de Active Directory, el uso de etiquetas de activos y los inventarios periódicos de activos pueden ayudar a garantizar que los hosts no se pierdan.
- Políticas de control de acceso (provisión/de-provisión de cuentas de usuario), mecanismos de multi-factor authentication.
- Procesos para la provisión y descomisionamiento de hosts (es decir, guía de hardening de seguridad base, imágenes doradas).
- Políticas de limpieza de Active Directory
  - `¿Se eliminan las cuentas de empleados anteriores o simplemente se deshabilitan?`
  - `¿Cuál es el proceso para eliminar registros obsoletos de Active Directory?`
  - Procesos para descomisionar sistemas operativos/servicios heredados (es decir, desinstalación adecuada de Exchange al migrar a 0365).
  - Programar una auditoría de usuarios, grupos y hosts.

### Technology

Revisar periódicamente Active Directory para detectar misconfiguraciones heredadas y nuevas amenazas emergentes. A medida que se realizan cambios en Active Directory, asegurarse de que no se introduzcan misconfiguraciones comunes. Prestar atención a cualquier vulnerabilidad introducida por Active Directory y las herramientas o aplicaciones utilizadas en el entorno.

- Ejecutar herramientas como BloodHound, PingCastle y Grouper periódicamente para identificar misconfiguraciones de Active Directory.
- Asegurarse de que los administradores no almacenen contraseñas en el campo de descripción de la cuenta de Active Directory.
- Revisar SYSVOL en busca de scripts que contengan contraseñas y otros datos sensibles.
- Evitar el uso de cuentas de servicio "normales", utilizando Group Managed (gMSA) y Managed Service Accounts (MSA) siempre que sea posible para mitigar el riesgo de Kerberoasting.
- Deshabilitar Unconstrained Delegation siempre que sea posible.
- Prevenir el acceso directo a Domain Controllers mediante el uso de hardened jump hosts.
- Considerar configurar el atributo `ms-DS-MachineAccountQuota` a `0`, lo que impide a los usuarios agregar cuentas de máquina y puede prevenir varios ataques como el ataque noPac y Resource-Based Constrained Delegation (RBCD).
- Deshabilitar el servicio de print spooler siempre que sea posible para prevenir varios ataques.
- Deshabilitar NTLM authentication para Domain Controllers si es posible.
- Usar Extended Protection for Authentication junto con la habilitación de Require SSL only para permitir solo conexiones HTTPS para los servicios de Certificate Authority Web Enrollment y Certificate Enrollment Web Service.
- Habilitar SMB signing y LDAP signing.
- Tomar medidas para prevenir la enumeración con herramientas como BloodHound.
- Idealmente, realizar penetration tests/AD security assessments trimestrales, pero si existen limitaciones presupuestarias, estos deberían realizarse al menos anualmente.
- Probar backups para verificar su validez y revisar/practicar planes de recuperación ante desastres.
- Habilitar la restricción de acceso anónimo y prevenir la enumeración de sesiones nulas configurando la clave de registro `RestrictNullSessAccess` a `1` para restringir el acceso de sesión nula a usuarios no autenticados.

---

## Protections By Section

Como una mirada diferente a esto, hemos desglosado las acciones significativas por sección y correlacionado controles basados en el TTP y una etiqueta MITRE. Cada etiqueta corresponde a una sección de la [Enterprise ATT&CK Matrix](https://attack.mitre.org/tactics/enterprise/) que se encuentra aquí. Cualquier etiqueta marcada como `TA` corresponde a una táctica general, mientras que una etiqueta marcada como `T###` es una técnica que se encuentra en la matriz bajo tácticas.

|**TTP**|**MITRE Tag**|

**Description**|
|---|---|---|
|`External Reconnaissance`|`T1589`|Esta parte de un ataque es extremadamente difícil de detectar y defender. Un atacante no tiene que interactuar directamente con tu entorno empresarial, por lo que es imposible saber cuándo está ocurriendo. Lo que se puede hacer es monitorear y controlar los datos que se publican al mundo. Las ofertas de trabajo, documentos (y los metadatos adjuntos), y otras fuentes de información abierta como registros BGP y DNS, revelan algo sobre tu empresa. Tener cuidado de `limpiar` los documentos antes de su publicación puede asegurar que un atacante no pueda obtener el contexto de nombres de usuario de ellos como un ejemplo. Lo mismo puede decirse de no proporcionar información detallada sobre herramientas y equipos utilizados en tus redes a través de ofertas de trabajo.|
|`Internal Reconnaissance`|`T1595`|Para la recopilación de información de nuestras redes internas, tenemos más opciones. A menudo se considera una fase activa y, como tal, generará tráfico de red que podemos monitorear y colocar defensas basadas en lo que vemos. `Monitorear el tráfico de red` en busca de ráfagas de paquetes de gran volumen de cualquier fuente o varias fuentes puede ser indicativo de escaneo. Un `Firewall` o `Network Intrusion Detection System` (`NIDS`) correctamente configurado detectará estas tendencias rápidamente y alertará sobre el tráfico. Dependiendo de la herramienta o dispositivo, incluso puede agregar una regla que bloquee proactivamente el tráfico de dichos hosts. La utilización del monitoreo de red junto con un SIEM puede ser crucial para detectar la recopilación de información. Ajustar adecuadamente la configuración del Firewall de Windows o tu EDR de elección para no responder al tráfico ICMP, entre otros tipos de tráfico, puede ayudar a negar a un atacante cualquier información que pueda obtener de los resultados.|
|`Poisoning`|`T1557`|Utilizar opciones de seguridad como `SMB message signing` y `encriptar el tráfico` con un mecanismo de encriptación fuerte hará mucho para detener los ataques de poisoning y man-in-the-middle. SMB signing utiliza códigos de autenticación hashed y verifica la identidad del remitente y receptor del paquete. Estas acciones romperán los ataques de relay ya que el atacante solo está falsificando el tráfico.|
|`Password Spraying`|`T1110/003`|Esta acción es quizás la más fácil de defender y detectar. El simple logging y monitoreo pueden alertarte de ataques de password spraying en tu red. Observar tus logs en busca de múltiples intentos de inicio de sesión viendo los `Event IDs 4624` y `4648` para cadenas de intentos inválidos puede alertarte sobre intentos de password spraying o fuerza bruta para acceder al host. Tener políticas de contraseñas fuertes, una política de bloqueo de cuentas configurada y utilizar autenticación de dos factores o multi-factor authentication pueden ayudar a prevenir el éxito de un ataque de password spraying. Para una mirada más profunda a las configuraciones de políticas recomendadas, consulta este [artículo](https://www.netsec.news/summary-of-the-nist-password-recommendations-for-2021/) y la documentación de [NIST](https://pages.nist.gov/800-63-3/sp800-63b.html).|
|`Credentialed Enumeration`|`TA0006`|No hay una defensa real que puedas poner en su lugar para detener este método de ataque. Una vez que un atacante tiene credenciales válidas, puede realizar cualquier acción que el usuario tenga permitido hacer. Sin embargo, un defensor vigilante puede detectar y detener esto. Monitorear actividades inusuales como emitir comandos desde la CLI cuando un usuario no debería tener necesidad de utilizarla. Múltiples solicitudes de RDP enviadas de host a host dentro de la red o el movimiento de archivos desde varios hosts pueden alertar a un defensor. Si un atacante logra adquirir privilegios administrativos, esto puede volverse mucho más difícil, pero hay herramientas de heurística de red que se pueden implementar para analizar constantemente la red en busca de actividad anómala. La segmentación de la red puede ayudar mucho aquí.|
|`LOTL`|N/A|Puede ser difícil detectar a un atacante mientras utiliza los recursos integrados en los sistemas operativos del host. Aquí es donde tener un `baseline of network traffic` y `user behavior` resulta útil. Si tus defensores comprenden cómo se ve la actividad de red regular día a día, tienes una oportunidad de detectar lo anormal. Observar shells de comandos y utilizar una política de `Applocker` adecuadamente configurada puede ayudar a prevenir el uso de aplicaciones y herramientas a las que los usuarios no deberían tener acceso o necesitar.|
|`Kerberoasting`|`T1558/003`|Kerberoasting como técnica de ataque está ampliamente documentada, y hay muchas formas de detectarla y defenderse contra ella. La forma número uno de protegerse contra Kerberoasting es `utilizar un esquema de encriptación más fuerte que RC4` para mecanismos de autenticación Kerberos. Aplicar políticas de contraseñas fuertes puede ayudar a prevenir que los ataques de Kerberoasting tengan éxito. `Utilizar Group Managed service accounts` es probablemente la mejor defensa ya que esto hace que Kerberoasting ya no sea posible. Realizar `auditorías` periódicas de los permisos de las cuentas de los usuarios en busca de membresía excesiva en grupos puede ser una forma efectiva de detectar problemas.|

### MITRE ATT&CK Breakdown

![text](https://academy.hackthebox.com/storage/modules/143/mitre.gif)

Quería tomar un segundo para mostrarles a todos cómo se ve al explorar el ATT&CK framework. Usaremos el ejemplo anterior de `Kerberoasting` para verlo a través de la lente del framework. Kerberoasting es parte de la `Tactic tag TA0006 Credential Access` (cuadro verde en la imagen de arriba). Las tácticas abarcan el objetivo general del actor y contendrán varias técnicas que se mapearán a ese objetivo. Dentro de este alcance, verás todo tipo de técnicas de robo de credenciales. Podemos desplazarnos hacia abajo y buscar `Steal or Forge Kerberos Tickets`, que es `Technique Tag T1558` (cuadro azul en la imagen de arriba). Esta técnica contiene cuatro sub-técnicas (indicadas por el `.00#` junto al nombre de la técnica) Golden Ticket, Silver Ticket, Kerberoasting y AS-REP Roasting. Dado que nos interesa Kerberoasting, seleccionaríamos la sub-técnica `T1558.003` (cuadro naranja en la imagen de arriba), y nos llevará a una nueva página. Aquí, podemos ver una explicación general de la técnica, la información que hace referencia a la clasificación de la plataforma ATT&CK en la parte superior derecha, ejemplos de su uso en el mundo real, formas de mitigar y detectar la táctica y, finalmente, referencias para obtener más información al final de la página.

Entonces, nuestra técnica se clasificaría bajo `TA0006/T1558.003`. Así es como se leería el árbol de Tactic/Technique. Hay muchas formas diferentes de navegar por el framework. Solo queríamos proporcionar alguna aclaración sobre lo que estábamos buscando y cómo estábamos definiendo tácticas frente a técnicas al hablar de MITRE ATT&CK en este módulo. Este framework es excelente para explorar si tienes curiosidad sobre una `Tactic` o `Technique` y quieres más información al respecto.

---

Estas no son una lista exhaustiva de medidas defensivas, pero son un buen comienzo. Como atacantes, si comprendemos las posibles medidas defensivas que podemos enfrentar durante nuestras evaluaciones, podemos planificar medios alternativos de explotación y movimiento. No ganaremos todas las batallas; algunos defensores pueden tener sus entornos cerrados herméticamente y ver cada movimiento que hagas, pero otros pueden haber pasado por alto una de estas recomendaciones. Es importante explorarlas todas y ayudar a proporcionar al equipo defensivo los mejores resultados posibles. Además, comprender cómo funcionan los ataques y las defensas nos hará mejorar como profesionales de ciberseguridad en general.