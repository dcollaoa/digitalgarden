A lo largo de este módulo, hemos dominado varias técnicas diferentes que se pueden usar desde una `perspectiva ofensiva`. Como penetration testers, también debemos preocuparnos por las mitigaciones y detecciones que se pueden implementar para ayudar a los defensores a detener este tipo de TTPs. Esto es crucial, ya que se espera que proporcionemos a nuestros clientes posibles soluciones a los problemas que encontramos y explotamos durante nuestras evaluaciones. Algunas de las soluciones pueden ser:

- Cambios físicos en el hardware
- Cambios en la infraestructura de red
- Modificaciones en las bases de los hosts

Esta sección cubrirá algunas de estas soluciones y lo que significan para nosotros y para aquellos encargados de defender la red.

---

## Setting a Baseline

Entender todo lo que está presente y sucede en un entorno de red es vital. Como defensores, deberíamos poder `identificar` e `investigar` rápidamente cualquier nuevo host que aparezca en nuestra red, cualquier nueva herramienta o aplicación que se instale en hosts fuera de nuestro catálogo de aplicaciones y cualquier tráfico de red nuevo o único generado. Se debe realizar una auditoría de todo lo que se enumera a continuación anualmente, si no cada pocos meses, para garantizar que sus registros estén actualizados. Algunas de las consideraciones con las que podemos comenzar son:

### Things to Document and Track

- Registros DNS, copias de seguridad de dispositivos de red y configuraciones DHCP
- Inventario completo y actual de aplicaciones
- Una lista de todos los hosts empresariales y su ubicación
- Usuarios con permisos elevados
- Una lista de cualquier host con múltiples interfaces de red (dual-homed hosts)
- Mantener un diagrama de red visual de su entorno

Además de rastrear los elementos anteriores, mantener un diagrama de red visual de su entorno actualizado puede ser muy efectivo al solucionar problemas o responder a un incidente. [Netbrain](https://www.netbraintech.com/) es un excelente ejemplo de una herramienta que puede proporcionar esta funcionalidad y acceso interactivo a todos los dispositivos en el diagrama. Si queremos una manera de documentar visualmente nuestro entorno de red, podemos usar una herramienta gratuita como [diagrams.net](https://app.diagrams.net/). Por último, para nuestra línea de base, comprender qué activos son críticos para el funcionamiento de su organización y monitorear esos activos es imprescindible.

---

## People, Processes, and Technology

El endurecimiento de la red se puede organizar en las categorías _Personas_, _Procesos_ y _Tecnología_. Estas medidas de endurecimiento abarcarán los aspectos de hardware, software y humanos de cualquier red. Comencemos con el aspecto `humano` (`People`).

### People

En incluso el entorno más endurecido, los usuarios a menudo se consideran el eslabón más débil. Hacer cumplir las mejores prácticas de seguridad para usuarios estándar y administradores evitará "victorias fáciles" para los pentesters y atacantes maliciosos. También debemos esforzarnos por mantenernos a nosotros mismos y a los usuarios a los que servimos educados y conscientes de las amenazas. Las siguientes medidas son una excelente manera de comenzar el proceso de asegurar el elemento humano de cualquier entorno empresarial.

### BYOD and Other Concerns

Bring Your Own Device (BYOD) se está volviendo prevalente en la fuerza laboral actual. Con la mayor aceptación del trabajo remoto y los arreglos de trabajo híbridos, más personas están utilizando sus dispositivos personales para realizar tareas relacionadas con el trabajo. Esto presenta riesgos únicos para las organizaciones porque sus empleados pueden estar conectándose a redes y recursos compartidos propiedad de la organización. La organización tiene una capacidad limitada para administrar y asegurar un dispositivo de propiedad personal como una laptop o un teléfono inteligente, dejando la responsabilidad de asegurar el dispositivo en gran medida con el propietario. Si el propietario del dispositivo sigue malas prácticas de seguridad, no solo se pone en riesgo de compromiso, sino que ahora también puede extender estos mismos riesgos a sus empleadores. Consideremos el ejemplo práctico a continuación para construir una perspectiva sobre esto:

Escenario: Nick es un gerente de logística trabajador y dedicado para Inlanefreight. Ha hecho un gran trabajo a lo largo de los años, y la compañía confía en él lo suficiente como para permitirle trabajar desde casa tres días a la semana. Al igual que muchos empleados de Inlanefreight, Nick también aprovecha la disposición de Inlanefreight para permitir que los empleados usen sus propios dispositivos para tareas relacionadas con el trabajo en casa y en los entornos de red de la oficina. Nick también disfruta de los videojuegos y, a veces, descarga ilegalmente videojuegos mediante torrents. Un juego que descargó e instaló también instaló malware que dio a un atacante acceso remoto a su laptop. Cuando Nick va a la oficina, se conecta a la red WiFi que extiende el acceso a la red de empleados. Cualquiera puede acceder a los Controladores de Dominio, Comparticiones de Archivos, impresoras y otros recursos de red importantes desde esta red. Debido a que hay malware en el sistema de Nick, el atacante también tiene acceso a estos recursos de red y puede intentar pivotar a través de la red de Inlanefreight debido a las malas prácticas de seguridad de Nick en su computadora personal.

Usar `multi-factor authentication` (algo que tienes, algo que sabes, algo que eres, ubicación, etc.) son todos excelentes factores a considerar al implementar mecanismos de autenticación. Implementar dos o más factores para la autenticación (especialmente para cuentas administrativas y acceso) es una excelente manera de dificultar que un atacante obtenga acceso completo a una cuenta en caso de que se comprometa la contraseña o el hash de un usuario.

Junto con asegurar que sus usuarios no puedan causar daño, debemos considerar nuestras políticas y procedimientos para el acceso y control de dominio. Las organizaciones más grandes también deberían considerar construir un equipo de Security Operation Center (SOC) o usar un `SOC as a Service` para monitorear constantemente lo que está sucediendo dentro del entorno de TI las 24 horas del día, los 7 días de la semana. Las tecnologías defensivas modernas han avanzado mucho y pueden ayudar con muchas tácticas defensivas diferentes, pero necesitamos operadores humanos para asegurarnos de que funcionen como deberían. La `respuesta a incidentes` es algo que aún no podemos automatizar completamente fuera del elemento humano. Por lo tanto, tener un `incident response plan` adecuado listo es esencial para estar preparado para una violación.

---

### Processes

Mantener y hacer cumplir políticas y procedimientos puede tener un impacto significativo en la postura general de seguridad de una organización. Es casi imposible responsabilizar a los empleados de una organización sin políticas definidas. Hace que sea difícil responder a un incidente sin procedimientos definidos y practicados, como un `disaster recovery plan`. Los elementos a continuación pueden ayudar a comenzar a definir los `processes`, `policies` y `procedures` de una organización en relación con asegurar a sus usuarios y el entorno de red.

- Políticas y procedimientos adecuados para el monitoreo y la gestión de activos
  - Las auditorías de hosts, el uso de etiquetas de activos y los inventarios periódicos de activos pueden ayudar a garantizar que los hosts no se pierdan.
- Políticas de control de acceso (provisionamiento/desprovisionamiento de cuentas de usuario), mecanismos de autenticación multifactor
- Procesos para provisionar y descomisionar hosts (es decir, guía de endurecimiento de seguridad de línea base, imágenes doradas)
- Procesos de gestión de cambios para documentar formalmente `quién hizo qué` y `cuándo lo hicieron`

### Technology

Revise periódicamente la red en busca de configuraciones incorrectas heredadas y nuevas amenazas emergentes. A medida que se realizan cambios en un entorno, asegúrese de que no se introduzcan configuraciones incorrectas comunes prestando atención a cualquier vulnerabilidad introducida por herramientas o aplicaciones utilizadas en el entorno. Si es posible, intente parchear o mitigar esos riesgos con la comprensión de que la tríada CIA es un acto de equilibrio, y la aceptación del riesgo que presenta una vulnerabilidad puede ser la mejor opción para su entorno.

---

## From the Outside Moving In

Cuando trabajamos con una organización para ayudarlos a evaluar la postura de seguridad de su entorno, puede ser útil comenzar desde el exterior y avanzar hacia adentro. Como penetration testers y profesionales de la seguridad, queremos que nuestros clientes tomen en serio nuestros hallazgos y recomendaciones para informar sus decisiones futuras. Queremos que comprendan que los problemas que descubrimos también pueden ser encontrados por individuos o grupos con intenciones menos honorables. Consideremos esto a través de un ejercicio mental utilizando el esquema a continuación. Siéntase libre de usar estas preguntas y consideraciones para iniciar una conversación con amigos, miembros del equipo o, si está solo, tome algunas notas y proponga el diseño más seguro que pueda imaginar:

### Perimeter First

- `¿Qué estamos protegiendo exactamente?`
- `¿Cuáles son los activos más valiosos que posee la organización y que necesitan protección?`
- `¿Qué se puede considerar el perímetro de nuestra red?`
- `¿Qué dispositivos y servicios se pueden acceder desde Internet? (Expuestos públicamente)`
- `¿Cómo podemos detectar y prevenir cuando un atacante está intentando un ataque?`
- `¿Cómo podemos asegurarnos de que la persona y/o equipo correcto reciba alertas tan pronto como algo no esté bien?`
- `¿Quién en nuestro equipo es responsable de monitorear alertas y cualquier acción que nuestros controles técnicos marquen como potencialmente maliciosa?`
- `¿Tenemos alguna confianza externa con socios externos?`
- `¿Qué tipos de mecanismos de autenticación estamos usando?`
- `¿Requerimos gestión Out-of-Band (OOB) para nuestra infraestructura? Si es así, ¿quién tiene permisos de acceso?`
- `¿Tenemos un plan de recuperación ante desast

res?`

Al considerar estas preguntas con respecto al perímetro, podemos enfrentar la realidad de que una organización tiene infraestructura que podría estar basada en las instalaciones y/o en la nube. La mayoría de las organizaciones en la actualidad operan infraestructuras híbridas en la nube. Esto significa que algunas de las tecnologías utilizadas por las organizaciones pueden estar funcionando en infraestructura de red y servidor propiedad de la organización, y algunas pueden estar alojadas por un proveedor de nube de terceros (AWS, Azure, GCP, etc.).

- Interfaz externa en un firewall
  - Capacidades de Next-Gen Firewall
    - Bloqueo de conexiones sospechosas por IP
    - Asegurar que solo personas aprobadas se conecten a VPNs
    - Construir la capacidad de desconectar rápidamente conexiones sospechosas sin interrumpir las funciones comerciales

---

### Internal Considerations

Muchas de las preguntas que hacemos para consideraciones externas se aplican a nuestro entorno interno. Hay algunas diferencias; sin embargo, hay muchas rutas diferentes para asegurar la defensa exitosa de nuestras redes. Consideremos lo siguiente:

- `¿Hay hosts que requieren exposición a Internet y están adecuadamente endurecidos y colocados en una red DMZ?`
- `¿Estamos utilizando sistemas de detección y prevención de intrusiones dentro de nuestro entorno?`
- `¿Cómo están configuradas nuestras redes? ¿Diferentes equipos están confinados a sus propios segmentos de red?`
- `¿Tenemos redes separadas para producción y redes de gestión?`
- `¿Cómo rastreamos a los empleados aprobados que tienen acceso remoto a redes administrativas/de gestión?`
- `¿Cómo correlacionamos los datos que recibimos de nuestras defensas de infraestructura y puntos finales?`
- `¿Estamos utilizando IDS, IPS y registros de eventos basados en host?`

Nuestra mejor oportunidad de detectar, detener y potencialmente incluso prevenir un ataque a menudo depende de nuestra capacidad para mantener la visibilidad dentro de nuestro entorno. Una implementación adecuada de SIEM para correlacionar y analizar nuestros registros de hosts e infraestructura puede ser de gran ayuda. Combine eso con una segmentación de red adecuada, y se vuelve infinitamente más difícil para un atacante obtener un punto de apoyo y pivotar hacia objetivos. Cosas simples como asegurar que Steve de RRHH no pueda ver o acceder a la infraestructura de red, como conmutadores y enrutadores, o paneles de administración para sitios web internos, pueden prevenir el uso de usuarios estándar para movimiento lateral.

---

## MITRE Breakdown

Como una mirada diferente a esto, hemos desglosado las principales acciones que practicamos en este módulo y mapeamos controles basados en el TTP y una etiqueta MITRE. Cada etiqueta corresponde a una sección de la [Enterprise ATT&CK Matrix](https://attack.mitre.org/tactics/enterprise/) que se encuentra aquí. Cualquier etiqueta marcada como `TA` corresponde a una táctica general, mientras que una etiqueta marcada como `T###` es una técnica que se encuentra en la matriz bajo tácticas.

|**TTP**|**MITRE Tag**|**Description**|
|---|---|---|
|`External Remote Services`|T1133|Tenemos opciones para la prevención cuando se trata del uso de servicios remotos externos. `Primero`, tener un firewall adecuado para segmentar nuestro entorno del resto de Internet y controlar el flujo de tráfico es una necesidad. `Segundo`, deshabilitar y bloquear cualquier protocolo de tráfico interno para que no alcance el mundo exterior es siempre una buena práctica. `Tercero`, usar una VPN u otro mecanismo que requiera que un host esté `lógicamente` ubicado dentro de la red antes de obtener acceso a esos servicios es una excelente manera de garantizar que no esté filtrando datos que no debería.|
|`Remote Services`|T1021|La autenticación multifactor puede ser muy útil cuando se intenta mitigar el uso no autorizado de servicios remotos como SSH y RDP. Incluso si se toma la contraseña de un usuario, el atacante aún necesitaría una manera de adquirir la cadena de su MFA de elección. Limitar las cuentas de usuario con permisos de acceso remoto y separar deberes sobre quién puede acceder remotamente a qué partes de una red puede ser muy útil. Utilizar el firewall de su red y el firewall incorporado en sus hosts para limitar las conexiones entrantes/salientes para los servicios remotos es una victoria fácil para los defensores. Detendrá el intento de conexión a menos que sea desde una red interna o externa autorizada. Cuando se trata de dispositivos de infraestructura como enrutadores y conmutadores, exponer solo servicios y puertos de gestión remota a una red Out Of Band (OOB) es una práctica recomendada que siempre se debe seguir. Hacer esto asegura que cualquier persona que pueda haber comprometido las redes empresariales no pueda simplemente saltar de un host de usuario regular a la infraestructura.|
|`Use of Non-Standard Ports`|T1571|Esta técnica puede ser difícil de detectar. Los atacantes a menudo usarán un protocolo común como `HTTP` o `HTTPS` para comunicarse con su entorno. Es difícil ver lo que está sucediendo, especialmente con el uso de HTTPS, pero las combinaciones de protocolos como estos con un puerto no estándar (44`4` en lugar de 44`3`, por ejemplo) pueden alertarnos de que algo sospechoso está sucediendo. Los atacantes a menudo intentarán trabajar de esta manera, por lo que tener una sólida `línea base` de qué puertos/protocolos se usan comúnmente en su entorno puede ser de gran ayuda cuando se intenta detectar lo malo. Usar algún tipo de sistema de prevención o detección de intrusiones en la red también puede ayudar a detectar y cerrar el tráfico potencialmente malicioso.|
|`Protocol Tunneling`|T1572|Este es un problema interesante de abordar. Muchos actores utilizan el túnel de protocolo para ocultar sus canales de comunicación. A menudo veremos cosas como las que practicamos en este módulo (túnel de otro tráfico a través de un túnel SSH) e incluso el uso de protocolos como DNS para pasar instrucciones de fuentes externas a un host interno a la red. Tomarse el tiempo para bloquear qué puertos y protocolos están permitidos para hablar dentro y fuera de sus redes es una necesidad. Si tiene un dominio en funcionamiento y está alojando un servidor DC y DNS, sus hosts no deberían tener ninguna razón para llegar externamente para la resolución de nombres. No permitir la resolución de DNS desde la web (excepto a hosts específicos como el servidor DNS) puede ayudar con un problema como este. Tener una buena solución de monitoreo en su lugar también puede vigilar los patrones de tráfico y lo que se conoce como `Beaconing`. Incluso si el tráfico está cifrado, es posible que veamos solicitudes que ocurren en un patrón a lo largo del tiempo. Este es un rasgo común de un canal C2.|
|`Proxy Use`|T1090|El uso de un punto de proxy es común entre los actores de amenazas. Muchos usarán un punto de proxy o distribuirán su tráfico en múltiples hosts para no exponer directamente su infraestructura. Al usar un proxy, no hay una conexión directa desde el entorno de la víctima al host del atacante en ningún momento. La detección y prevención del uso de proxy es un poco difícil, ya que requiere un conocimiento íntimo del flujo de red común dentro de su entorno. La ruta más efectiva es mantener una lista de dominios y direcciones IP permitidos/bloqueados. Cualquier cosa no explícitamente permitida será bloqueada hasta que permita el tráfico.|
|`LOTL`|N/A|Puede ser difícil detectar a un atacante mientras utiliza los recursos disponibles. Aquí es donde tener una línea base del tráfico de red y el comportamiento del usuario es útil. Si sus defensores entienden cómo es el día a día normal de su red, tienen una oportunidad de detectar lo anormal. Observar las shells de comando y utilizar una solución EDR y AV adecuadamente configurada será de gran ayuda para proporcionar visibilidad. Tener algún tipo de monitoreo y registro de red que alimente a un sistema común como un SIEM que los defensores verifiquen, será de gran ayuda para ver un ataque en las etapas iniciales en lugar de después de los hechos.