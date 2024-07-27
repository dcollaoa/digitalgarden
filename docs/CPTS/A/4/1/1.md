Cada organización debe realizar diferentes tipos de `Security assessments` en sus `networks`, `computers` y `applications` al menos de vez en cuando. El propósito principal de la mayoría de los tipos de evaluaciones de seguridad es encontrar y confirmar que existen vulnerabilidades, para que podamos trabajar en `patch`, `mitigate` o `remove` dichas vulnerabilidades. Hay diferentes formas y metodologías para probar cuán seguro es un sistema informático. Algunos tipos de evaluaciones de seguridad son más apropiados para ciertas redes que otros. Pero todos tienen el propósito de mejorar la ciberseguridad. Todas las organizaciones tienen diferentes requisitos de cumplimiento y tolerancia al riesgo, enfrentan diferentes amenazas y tienen diferentes modelos comerciales que determinan los tipos de sistemas que ejecutan externamente e internamente. Algunas organizaciones tienen una postura de seguridad mucho más madura que sus pares y pueden enfocarse en simulaciones avanzadas de red team realizadas por terceros, mientras que otras todavía están trabajando para establecer una seguridad básica. Independientemente, todas las organizaciones deben estar al tanto de las vulnerabilidades tanto heredadas como recientes y tener un sistema para detectar y mitigar los riesgos para sus sistemas y datos.

## Vulnerability Assessment

Los `Vulnerability assessments` son apropiados para todas las organizaciones y redes. Una evaluación de vulnerabilidades se basa en un estándar de seguridad particular, y se analiza el cumplimiento de estos estándares (por ejemplo, pasando por una lista de verificación).

Una evaluación de vulnerabilidades puede basarse en varios estándares de seguridad. Qué estándares se aplican a una red en particular dependerá de muchos factores. Estos factores pueden incluir regulaciones de seguridad de datos específicas de la industria y la región, el tamaño y la forma de la red de una empresa, qué tipos de aplicaciones utilizan o desarrollan y su nivel de madurez en seguridad.

Las evaluaciones de vulnerabilidades pueden realizarse de forma independiente o junto con otras evaluaciones de seguridad, dependiendo de la situación de una organización.

## Penetration Test

Aquí en `Hack The Box`, nos encantan las pruebas de penetración, también conocidas como pentests. Nuestros laboratorios y muchos de nuestros otros cursos de la Academia se centran en el pentesting.

Se llaman pruebas de penetración porque los testers las realizan para determinar si y cómo pueden penetrar una red. Un pentest es un tipo de ataque cibernético simulado, y los pentesters realizan acciones que un actor de amenazas podría realizar para ver si ciertos tipos de exploits son posibles. La diferencia clave entre un pentest y un ataque cibernético real es que el primero se realiza con el consentimiento legal completo de la entidad que se está testeando. Ya sea que un pentester sea un empleado o un contratista externo, necesitará firmar un documento legal extenso con la empresa objetivo que describe lo que se les permite hacer y lo que no se les permite hacer.

Al igual que con una evaluación de vulnerabilidades, un pentest efectivo resultará en un informe detallado lleno de información que puede usarse para mejorar la seguridad de la red. Se pueden realizar todo tipo de pentests según las necesidades específicas de una organización.

El pentesting de `Black box` se realiza sin conocimiento de la configuración o aplicaciones de la red. Típicamente, se le dará al tester acceso a la red (o un puerto ethernet y tendrán que eludir Network Access Control NAC) y nada más (requiriendo que realicen su propio descubrimiento de direcciones IP) si el pentest es interno, o nada más que el nombre de la empresa si el pentest es desde una perspectiva externa. Este tipo de pentesting generalmente es realizado por terceros desde la perspectiva de un atacante `external`. A menudo, el cliente le pedirá al pentester que les muestre las direcciones IP internas/externas descubiertas/rangos de red para que puedan confirmar la propiedad y anotar cualquier host que deba considerarse fuera del alcance.

El pentesting de `Grey box` se realiza con un poco de conocimiento de la red que están testeando, desde una perspectiva equivalente a un `employee` que no trabaja en el departamento de TI, como un `receptionist` o `customer service agent`. El cliente típicamente le dará al tester rangos de red en el alcance o direcciones IP individuales en una situación de grey box.

El pentesting de `White box` típicamente se realiza dando al pentester acceso completo a todos los sistemas, configuraciones, documentos de construcción, etc., y al código fuente si las aplicaciones web están en el alcance. El objetivo aquí es descubrir la mayor cantidad de fallos posibles que serían difíciles o imposibles de descubrir a ciegas en un tiempo razonable.

A menudo, los pentesters se especializan en un área particular. Los pentesters deben tener conocimiento de muchas tecnologías diferentes, pero generalmente tendrán una especialidad.

Los pentesters de `Application` evalúan aplicaciones web, aplicaciones de thick-client, APIs y aplicaciones móviles. A menudo estarán bien versados en la revisión de código fuente y podrán evaluar una aplicación web dada desde una perspectiva de black box o white box (típicamente una revisión de código seguro).

Los pentesters de `Network` o `infrastructure` evalúan todos los aspectos de una red informática, incluidos sus `networking devices` como routers y firewalls, estaciones de trabajo, servidores y aplicaciones. Este tipo de pentesters típicamente deben tener una fuerte comprensión de networking, Windows, Linux, Active Directory y al menos un lenguaje de scripting. Los escáneres de vulnerabilidades de red, como `Nessus`, pueden usarse junto con otras herramientas durante el pentesting de red, pero el escaneo de vulnerabilidades de red es solo una parte de un pentest adecuado. Es importante notar que hay diferentes tipos de pentests (evasivo, no evasivo, híbrido evasivo). Un escáner como Nessus solo se usaría durante un pentest no evasivo cuyo objetivo es encontrar la mayor cantidad de fallos en la red posible. Además, el escaneo de vulnerabilidades solo sería una pequeña parte de este tipo de prueba de penetración. Los escáneres de vulnerabilidades son útiles pero limitados y no pueden reemplazar el toque humano y otras herramientas y técnicas.

Los pentesters de `Physical` intentan aprovechar debilidades de seguridad física y fallos en los procesos para obtener acceso a una instalación como un centro de datos o edificio de oficinas.

- ¿Puedes abrir una puerta de una manera no prevista?
- ¿Puedes seguir a alguien hasta el centro de datos?
- ¿Puedes arrastrarte por un conducto de ventilación?

Los pentesters de `Social engineering` prueban a los seres humanos.

- ¿Pueden los empleados ser engañados por phishing, vishing (phishing por teléfono) u otras estafas?
- ¿Puede un pentester de ingeniería social acercarse a un recepcionista y decir, "sí, trabajo aquí"?

El pentesting es más apropiado para organizaciones con un nivel de madurez en seguridad medio o alto. La madurez en seguridad mide cuán desarrollado está el programa de ciberseguridad de una empresa, y la madurez en seguridad lleva años de construcción. Involucra la contratación de profesionales de ciberseguridad conocedores, tener políticas de seguridad bien diseñadas y su aplicación (como configuración, parcheo y gestión de vulnerabilidades), estándares de endurecimiento básicos para todos los tipos de dispositivos en la red, cumplimiento normativo fuerte, planes de respuesta a incidentes cibernéticos bien ejecutados, un `CSIRT` (`computer security incident response team`) experimentado, un proceso de control de cambios establecido, un `CISO` (`chief information security officer`), un `CTO` (`chief technical officer`), pruebas de seguridad frecuentes realizadas a lo largo de los años y una cultura de seguridad fuerte. La cultura de seguridad se trata de la actitud y los hábitos que los empleados tienen hacia la ciberseguridad. Parte de esto se puede enseñar a través de programas de concienciación sobre seguridad y parte integrando la seguridad en la cultura de la empresa. Todos, desde secretarios hasta sysadmins y personal de nivel C, deben ser conscientes de la seguridad, entender cómo evitar prácticas riesgosas y estar educados para reconocer actividades sospechosas que deben ser reportadas al personal de seguridad.

Las organizaciones con un nivel de madurez en seguridad más bajo pueden querer centrarse en las evaluaciones de vulnerabilidades porque un pentest podría encontrar demasiadas vulnerabilidades para ser útil y podría abrumar al personal encargado de la remediación. Antes de considerar el pentesting, debe haber un historial de evaluaciones de vulnerabilidades y acciones tomadas en respuesta a las evaluaciones de vulnerabilidades.

## Vulnerability Assessments vs. Penetration Tests

`Vulnerability Assessments` y Penetration Tests son dos evaluaciones completamente diferentes. Las evaluaciones de vulnerabilidades buscan vulnerabilidades en las redes sin simular ataques cibernéticos. Todas las empresas deben realizar evaluaciones de vulnerabilidades de vez en cuando. Una amplia variedad de estándares de seguridad podrían usarse para una evaluación de vulnerabilidades, como el cumplimiento de GDPR o los estándares de seguridad de aplicaciones web de OWASP. Una evaluación de vulnerabilidades pasa por una lista de verificación.

- ¿Cumplimos este estándar?
- ¿Tenemos esta configuración?

Durante una evaluación de vulnerabilidades, el evaluador generalmente ejecutará un escaneo de vulnerabilidades y luego realizará la validación de vulnerabilidades críticas, altas y de riesgo medio. Esto significa que mostrarán evidencia de que la vulnerabilidad existe y no es un falso positivo, a menudo usando otras herramientas, pero no buscarán realizar escalada de privilegios, movimiento lateral, post-explotación, etc., si validan, por ejemplo, una vulnerabilidad de ejecución remota de código.

`Penetration tests`, dependiendo de su tipo, evalúan la seguridad de diferentes activos y el impacto de los problemas presentes en el entorno. Los penetration tests pueden incluir tácticas

 manuales y automatizadas para evaluar la postura de seguridad de una organización. También suelen dar una mejor idea de cuán seguros son los activos de una empresa desde una perspectiva de prueba. Un `pentest` es un ataque cibernético simulado para ver si y cómo se puede penetrar la red. Independientemente del tamaño de la empresa, la industria o el diseño de la red, los pentests solo deben realizarse después de que se hayan realizado algunas evaluaciones de vulnerabilidades con éxito y se hayan solucionado los problemas. Una empresa puede realizar evaluaciones de vulnerabilidades y pentests en el mismo año. Se pueden complementar entre sí. Pero son tipos de pruebas de seguridad muy diferentes utilizadas en diferentes situaciones, y una no es "mejor" que la otra.

![pentestvsva](https://academy.hackthebox.com/storage/modules/108/graphics/VulnerabilityAssessment_Diagram_02.png) _Adaptado del gráfico original encontrado [aquí](https://predatech.co.uk/wp-content/uploads/2021/01/Vulnerability-Assessment-vs-Penetration-Testing-min-2.png)._

Una organización puede beneficiarse más de una `vulnerability assessment` en lugar de una prueba de penetración si desean recibir una visión de los problemas comúnmente conocidos de manera mensual o trimestral por parte de un proveedor externo. Sin embargo, una organización se beneficiaría más de una `penetration test` si están buscando un enfoque que utilice técnicas manuales y automatizadas para identificar problemas fuera de lo que identificaría un escáner de vulnerabilidades durante una evaluación de vulnerabilidades. Una prueba de penetración también podría ilustrar una cadena de ataque real que un atacante podría utilizar para acceder al entorno de una organización. Las personas que realizan pruebas de penetración tienen experiencia especializada en pruebas de red, pruebas inalámbricas, ingeniería social, aplicaciones web y otras áreas.

Para las organizaciones que reciben evaluaciones de pruebas de penetración de manera anual o semestral, sigue siendo crucial que esas organizaciones evalúen regularmente su entorno con escaneos de vulnerabilidades internos para identificar nuevas vulnerabilidades a medida que se publican al público por parte de los proveedores.

## Otros Tipos de Evaluaciones de Seguridad

Las evaluaciones de vulnerabilidades y las pruebas de penetración no son los únicos tipos de evaluaciones de seguridad que una organización puede realizar para proteger sus activos. Otros tipos de evaluaciones también pueden ser necesarios, dependiendo del tipo de organización.

### Security Audits

Las evaluaciones de vulnerabilidades se realizan porque una organización elige llevarlas a cabo y pueden controlar cómo y cuándo se evalúan. Las auditorías de seguridad son diferentes. Los `Security audits` son típicamente requisitos de fuera de la organización y generalmente son mandatados por `government agencies` o `industry associations` para asegurar que una organización cumpla con regulaciones de seguridad específicas.

Por ejemplo, todos los minoristas en línea y fuera de línea, restaurantes y proveedores de servicios que aceptan tarjetas de crédito importantes (Visa, MasterCard, AMEX, etc.) deben cumplir con el [PCI-DSS "Payment Card Industry Data Security Standard"](https://www.pcicomplianceguide.org/faq/#1). PCI DSS es una regulación impuesta por el [Payment Card Industry Security Standards Council](https://www.pcisecuritystandards.org/), una organización dirigida por compañías de tarjetas de crédito y entidades de la industria de servicios financieros. Una empresa que acepta pagos con tarjetas de crédito y débito puede ser auditada para el cumplimiento de PCI DSS, y la falta de cumplimiento podría resultar en multas y en la prohibición de aceptar esos métodos de pago.

Independientemente de las regulaciones por las que una organización pueda ser auditada, es su responsabilidad realizar evaluaciones de vulnerabilidades para asegurar que cumplan antes de estar sujetos a una auditoría de seguridad sorpresa.

### Bug Bounties

Los `Bug bounty programs` son implementados por todo tipo de organizaciones. Invitan a miembros del público en general, con algunas restricciones (usualmente sin escaneo automatizado), a encontrar vulnerabilidades de seguridad en sus aplicaciones. Los cazadores de recompensas por bugs pueden recibir desde unos pocos cientos de dólares hasta cientos de miles de dólares por sus hallazgos, lo cual es un precio pequeño a pagar para que una empresa evite que una vulnerabilidad crítica de ejecución remota de código caiga en las manos equivocadas.

Las grandes empresas con una gran base de clientes y una alta madurez en seguridad son apropiadas para los programas de bug bounty. Necesitan tener un equipo dedicado a clasificar y analizar los informes de bugs y estar en una situación donde puedan soportar que externos busquen vulnerabilidades en sus productos.

Empresas como Microsoft y Apple son ideales para tener programas de bug bounty debido a sus millones de clientes y robusta madurez en seguridad.

### Red Team Assessment

Las empresas con mayores presupuestos y más recursos pueden contratar sus propios `red teams` dedicados o utilizar los servicios de firmas consultoras externas para realizar evaluaciones de red team. Un red team consiste en profesionales de seguridad ofensiva que tienen una experiencia considerable en pruebas de penetración. Un red team juega un papel vital en la postura de seguridad de una organización.

Un red team es un tipo de pentesting black box evasivo, simulando todo tipo de ataques cibernéticos desde la perspectiva de un actor de amenazas externo. Estas evaluaciones típicamente tienen un objetivo final (por ejemplo, alcanzar un servidor crítico o una base de datos, etc.). Los evaluadores solo informan las vulnerabilidades que llevaron a la finalización del objetivo, no tantas vulnerabilidades como sea posible, como en una prueba de penetración.

Si una empresa tiene su propio red team interno, su trabajo es realizar pruebas de penetración más dirigidas con un conocimiento interno de su red. Un red team debe estar constantemente involucrado en campañas de red teaming. Las campañas podrían basarse en nuevos exploits cibernéticos descubiertos a través de las acciones de `advanced persistent threat groups` (`APTs`), por ejemplo. Otras campañas podrían apuntar a tipos específicos de vulnerabilidades para explorarlas en detalle una vez que una organización haya sido informada de ellas.

Idealmente, si una empresa puede permitírselo y ha estado construyendo su madurez en seguridad, debería realizar evaluaciones de vulnerabilidades regulares por sí misma, contratar terceros para realizar pruebas de penetración o evaluaciones de red team y, si es apropiado, construir un red team interno para realizar pentesting de grey y white box con parámetros y alcances más específicos.

### Purple Team Assessment

Un `blue team` consiste en especialistas en seguridad defensiva. Estas son a menudo personas que trabajan en un SOC (centro de operaciones de seguridad) o un CSIRT (equipo de respuesta a incidentes de seguridad informática). A menudo, también tienen experiencia en forense digital. Así que si los blue teams son defensivos y los red teams son ofensivos, rojo mezclado con azul es púrpura.

`¿Qué es un purple team?`

Los `Purple teams` se forman cuando los especialistas en seguridad `offensive` y `defensive` trabajan juntos con un objetivo común, mejorar la seguridad de su red. Los red teams encuentran problemas de seguridad y los blue teams aprenden sobre esos problemas de sus red teams y trabajan para solucionarlos. Una evaluación de purple team es como una evaluación de red team, pero el blue team también está involucrado en cada paso. El blue team puede incluso desempeñar un papel en el diseño de campañas. "Necesitamos mejorar nuestro cumplimiento de PCI DSS. Así que vamos a ver cómo el red team realiza una prueba de penetración en nuestros sistemas de punto de venta y proporcionar comentarios y retroalimentación activa durante su trabajo."

---

## Moving on

Ahora que hemos revisado los tipos clave de evaluaciones que una organización puede realizar, vamos a profundizar en las evaluaciones de vulnerabilidades para entender mejor los términos clave y una metodología de muestra.