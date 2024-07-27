Durante un `red team engagement`, `penetration test` o una `Active Directory assessment`, a menudo nos encontramos en una situación en la que ya hemos comprometido las `credentials`, `ssh keys`, `hashes` o `access tokens` necesarios para movernos a otro host, pero puede que no haya otro host directamente accesible desde nuestro host de ataque. En tales casos, es posible que necesitemos usar un `pivot host` que ya hemos comprometido para encontrar una forma de llegar a nuestro siguiente objetivo. Una de las cosas más importantes que hacer al aterrizar en un host por primera vez es verificar nuestro `privilege level`, `network connections` y el posible `VPN or other remote access software`. Si un host tiene más de un adaptador de red, probablemente podamos usarlo para movernos a un segmento de red diferente. Pivoting es esencialmente la idea de `moverse a otras redes a través de un host comprometido para encontrar más objetivos en diferentes segmentos de red`.

Existen muchos términos diferentes utilizados para describir un host comprometido que podemos usar para `pivot` a un segmento de red previamente inaccesible. Algunos de los más comunes son:

- `Pivot Host`
- `Proxy`
- `Foothold`
- `Beach Head system`
- `Jump Host`

El uso principal de Pivoting es vencer la segmentación (tanto física como virtual) para acceder a una red aislada. `Tunneling`, por otro lado, es un subconjunto de pivoting. Tunneling encapsula el tráfico de red en otro protocolo y lo enruta a través de él. Piénsalo de esta manera:

Tenemos una `key` que necesitamos enviar a un socio, pero no queremos que nadie que vea nuestro paquete sepa que es una llave. Entonces conseguimos un juguete de peluche y escondemos la llave dentro con instrucciones sobre lo que hace. Luego empaquetamos el juguete y se lo enviamos a nuestro socio. Cualquiera que inspeccione la caja verá un simple juguete de peluche, sin darse cuenta de que contiene algo más. Solo nuestro socio sabrá que la llave está escondida adentro y aprenderá cómo acceder y usarla una vez entregada.

Aplicaciones típicas como VPNs o navegadores especializados son solo otra forma de tunelizar el tráfico de red.

---

Inevitablemente nos encontraremos con varios términos diferentes usados para describir lo mismo en la industria de IT y Infosec. Con pivoting, notaremos que a menudo se refiere a esto como `Lateral Movement`.

`¿No es lo mismo que pivoting?`

La respuesta a eso es no exactamente. Tomémonos un segundo para comparar y contrastar `Lateral Movement` con `Pivoting and Tunneling`, ya que puede haber algo de confusión en cuanto a por qué algunos los consideran conceptos diferentes.

---

## Lateral Movement, Pivoting, and Tunneling Compared

#### Lateral Movement

Lateral movement puede describirse como una técnica utilizada para extender nuestro acceso a `hosts`, `applications` y `services` adicionales dentro de un entorno de red. Lateral movement también puede ayudarnos a acceder a recursos específicos del dominio que podamos necesitar para elevar nuestros privilegios. Lateral Movement a menudo permite la escalada de privilegios a través de hosts. Además de la explicación que hemos proporcionado para este concepto, también podemos estudiar cómo otras organizaciones respetadas explican Lateral Movement. Echa un vistazo a estas dos explicaciones cuando tengas tiempo:

[Palo Alto Network's Explanation](https://www.paloaltonetworks.com/cyberpedia/what-is-lateral-movement)

[MITRE's Explanation](https://attack.mitre.org/tactics/TA0008/)

Un ejemplo práctico de `Lateral Movement` sería:

Durante una evaluación, obtuvimos acceso inicial al entorno objetivo y pudimos tomar el control de la cuenta del administrador local. Realizamos un escaneo de red y encontramos tres hosts Windows más en la red. Intentamos usar las mismas credenciales del administrador local, y uno de esos dispositivos compartía la misma cuenta de administrador. Usamos las credenciales para movernos lateralmente a ese otro dispositivo, permitiéndonos comprometer aún más el dominio.

#### Pivoting

Utilizando múltiples hosts para cruzar fronteras de `network` a las que normalmente no tendrías acceso. Esto es más un objetivo específico. El objetivo aquí es permitirnos movernos más profundamente en una red comprometiendo hosts o infraestructuras específicas.

Un ejemplo práctico de `Pivoting` sería:

Durante un compromiso difícil, el objetivo tenía su red separada física y lógicamente. Esta separación hacía difícil que nos moviéramos y completáramos nuestros objetivos. Tuvimos que buscar en la red y comprometer un host que resultó ser la estación de trabajo de ingeniería utilizada para mantener y monitorear equipos en el entorno operativo, enviar informes y realizar otras tareas administrativas en el entorno empresarial. Ese host resultó tener dos tarjetas de red (conectadas a diferentes redes). Sin su acceso a ambas redes, empresarial y operativa, no habríamos podido pivotar como necesitábamos para completar nuestra evaluación.

#### Tunneling

A menudo nos encontramos usando varios protocolos para transportar tráfico dentro/fuera de una red donde existe la posibilidad de que nuestro tráfico sea detectado. Por ejemplo, usando HTTP para ocultar nuestro tráfico de Command & Control desde un servidor que poseemos hasta el host víctima. La clave aquí es la ofuscación de nuestras acciones para evitar la detección el mayor tiempo posible. Utilizamos protocolos con medidas de seguridad mejoradas como HTTPS sobre TLS o SSH sobre otros protocolos de transporte. Este tipo de acciones también permiten tácticas como la exfiltración de datos de una red objetivo o la entrega de más payloads e instrucciones en la red.

Un ejemplo práctico de `Tunneling` sería:

Una forma en que usamos Tunneling fue para diseñar nuestro tráfico para ocultarse en HTTP y HTTPS. Esta es una forma común en la que manteníamos el Command and Control (C2) de los hosts que habíamos comprometido dentro de una red. Ocultamos nuestras instrucciones dentro de las solicitudes GET y POST que parecían tráfico normal y, para el ojo inexperto, parecerían una solicitud o respuesta web a cualquier sitio. Si el paquete estaba bien formado, se reenviaría a nuestro servidor de control. Si no lo estaba, se redirigiría a otro sitio web, potencialmente desviando al defensor que lo revisaba.

Para resumir, debemos considerar estas tácticas como cosas separadas. Lateral Movement nos ayuda a extendernos ampliamente dentro de una red, elevando nuestros privilegios, mientras que Pivoting nos permite adentrarnos más en las redes, accediendo a entornos previamente inaccesibles. Ten en cuenta esta comparación mientras avanzas en este módulo.

---

Ahora que hemos sido introducidos al módulo y hemos definido y comparado Lateral Movement, Pivoting y Tunneling, vamos a sumergirnos en algunos de los conceptos de networking que nos permiten realizar estas tácticas.