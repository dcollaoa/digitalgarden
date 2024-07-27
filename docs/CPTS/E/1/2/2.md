Nuestra estructura de informe variará ligeramente según la evaluación que se nos asigne realizar. En este módulo, nos centraremos principalmente en un informe de Internal Penetration Test donde el tester logró comprometer el dominio de Active Directory (AD) durante un Internal Penetration Test. El informe con el que trabajaremos mostrará los elementos típicos de un informe de Internal Penetration Test. Discutiremos aspectos de otros informes (como apéndices adicionales que pueden incluirse en un External Penetration Test report). No es raro ver un External Penetration Test report que resulte en un compromiso interno con una cadena de ataque y otros elementos que cubriremos. La principal diferencia en nuestro laboratorio es que no incluiremos datos OSINT/información pública como direcciones de correo electrónico, subdominios, credenciales en brechas de seguridad, datos de registro/propiedad de dominios, etc., porque no estamos probando contra una empresa real con presencia en internet. Aunque hay algunos jugadores veteranos que tienen poder de permanencia como Have I Been Pwned, Shodan e Intelx, las herramientas de OSINT también son generalmente muy fluidas, por lo que, para cuando se publique este curso, la mejor herramienta o recurso para recopilar esa información puede haber cambiado. En su lugar, enumeramos algunos tipos comunes de información dirigida para ayudar en una penetración test y dejamos al lector probar y descubrir qué herramientas o APIs proporcionan los mejores resultados. Siempre es una buena idea no depender de una sola herramienta, por lo que se deben ejecutar múltiples y ver la diferencia en los datos.

- Registros públicos de DNS y propiedad de dominio
- Direcciones de correo electrónico
  - Luego, puede usarlas para verificar si alguna ha estado involucrada en una brecha o usar Google Dorks para buscarlas en sitios como Pastebin
- Subdominios
- Proveedores de terceros
- Dominios similares
- Recursos de nube pública

Estos tipos de recopilación de información se cubren en otros módulos como [Information Gathering - Web Edition](https://academy.hackthebox.com/course/preview/information-gathering---web-edition), [OSINT: Corporate Recon](https://academy.hackthebox.com/course/preview/osint-corporate-recon), y [Footprinting](https://academy.hackthebox.com/course/preview/footprinting) y están fuera del alcance de este módulo.

---

## Differences Across Assessment Types

Antes de recorrer los diversos tipos de informes disponibles y luego profundizar en los componentes de un Penetration Test report, definamos algunos tipos clave de evaluaciones.

### Vulnerability Assessment

Las vulnerability assessments implican ejecutar un escaneo automatizado de un entorno para enumerar vulnerabilidades. Estos pueden ser autenticados o no autenticados. No se intenta explotación, pero a menudo buscamos validar los resultados del escáner para que nuestro informe pueda mostrar a un cliente qué resultados del escáner son problemas reales y cuáles son falsos positivos. La validación puede consistir en realizar una verificación adicional para confirmar que se está utilizando una versión vulnerable o que hay una configuración/misconfiguración en su lugar, pero el objetivo no es obtener un punto de apoyo y moverse lateral/verticalmente. Algunos clientes incluso pedirán resultados de escaneo sin validación.

### Internal vs External

Un escaneo externo se realiza desde la perspectiva de un usuario anónimo en internet que apunta a los sistemas públicos de la organización. Un escaneo interno se realiza desde la perspectiva de un escáner en la red interna e investiga los hosts desde detrás del firewall. Esto se puede hacer desde la perspectiva de un usuario anónimo en la red corporativa del usuario, emulando un servidor comprometido, o en varios escenarios diferentes. Un cliente incluso puede pedir que se realice un escaneo interno con credenciales, lo que puede llevar a muchos más resultados del escáner para examinar, pero también producirá resultados más precisos y menos genéricos.

### Report Contents

Estos informes suelen centrarse en temas que se pueden observar en los resultados del escaneo y destacan la cantidad de vulnerabilidades y sus niveles de gravedad. Estos escaneos pueden producir MUCHOS datos, por lo que identificar patrones y mapearlos a deficiencias procedimentales es importante para evitar que la información se vuelva abrumadora.

---

## Penetration Testing

El penetration testing va más allá de los escaneos automatizados y puede aprovechar los datos de escaneos de vulnerabilidades para ayudar a guiar la explotación. Al igual que los escaneos de vulnerabilidades, estos se pueden realizar desde una perspectiva interna o externa. Dependiendo del tipo de penetration test (por ejemplo, un evasive test), es posible que no realicemos ningún tipo de escaneo de vulnerabilidades en absoluto.

Un penetration test puede realizarse desde diversas perspectivas, como "`black box`," donde no tenemos más información que el nombre de la empresa durante un externo o una conexión de red para un interno, "`grey box`" donde solo se nos dan direcciones IP/CIDR network ranges dentro del alcance, o "`white box`" donde se nos pueden dar credenciales, código fuente, configuraciones y más. Las pruebas se pueden realizar con `zero evasion` para intentar descubrir tantas vulnerabilidades como sea posible, desde un punto de vista `hybrid evasive` para probar las defensas del cliente comenzando de manera evasiva y gradualmente volviéndose "más ruidosos" para ver a qué nivel los equipos de seguridad interna/herramientas de monitoreo nos detectan y bloquean. Normalmente, una vez que se nos detecta en este tipo de evaluación, el cliente nos pedirá que pasemos a pruebas no evasivas para el resto de la evaluación. Este es un gran tipo de evaluación para recomendar a clientes con algunas defensas en su lugar pero sin una postura de seguridad defensiva altamente madura. Puede ayudar a mostrar brechas en sus defensas y dónde deben concentrar esfuerzos en mejorar sus reglas de detección y prevención. Para clientes más maduros, este tipo de evaluación puede ser una gran prueba de sus defensas y procedimientos internos para asegurarse de que todas las partes desempeñen correctamente sus roles en caso de un ataque real.

Finalmente, se nos puede pedir que realicemos `evasive testing` durante toda la evaluación. En este tipo de evaluación, intentaremos permanecer sin ser detectados el mayor tiempo posible y ver qué tipo de acceso, si es que hay alguno, podemos obtener mientras trabajamos de manera sigilosa. Esto puede ayudar a simular a un atacante más avanzado. Sin embargo, este tipo de evaluación a menudo está limitado por restricciones de tiempo que no están en su lugar para un atacante del mundo real. Un cliente también puede optar por una simulación de adversario a más largo plazo que puede ocurrir durante varios meses, con pocos empleados de la empresa conscientes de la evaluación y pocos o ningún empleado del cliente sabiendo la fecha/hora exacta de inicio de la evaluación. Este tipo de evaluación es adecuada para organizaciones con una mayor madurez en seguridad y requiere un conjunto de habilidades un poco diferente al de un penetration tester de red/aplicación tradicional.

### Internal vs External

Similar a las perspectivas de escaneo de vulnerabilidades, las external penetration testing normalmente se realizan desde la perspectiva de un atacante anónimo en internet. Puede aprovechar datos OSINT/información pública para intentar acceder a datos sensibles a través de aplicaciones o la red interna atacando hosts expuestos a internet. Las internal penetration testing pueden realizarse como un usuario anónimo en la red interna o como un usuario autenticado. Se realizan típicamente para encontrar tantas fallas como sea posible para obtener un punto de apoyo, realizar escalada de privilegios horizontal y vertical, moverse lateralmente y comprometer la red interna (típicamente el entorno de Active Directory del cliente).

---

## Inter-Disciplinary Assessments

Algunas evaluaciones pueden requerir la participación de personas con habilidades diversas que se complementan entre sí. Aunque logísticamente más complejas, tienden a ser de manera orgánica más colaborativas entre el equipo de consultoría y el cliente, lo que agrega un tremendo valor a la evaluación y confianza en la relación. Algunos ejemplos de estos tipos de evaluaciones incluyen:

### Purple Team Style Assessments

Como su nombre lo indica, es un esfuerzo combinado entre los equipos blue y red, más comúnmente un penetration tester y un incident responder. El concepto general es que el penetration tester simula una amenaza dada, y el incident responder trabaja con el equipo blue interno para revisar su conjunto de herramientas existentes para determinar si la alerta está configurada correctamente o si se necesitan ajustes para permitir la identificación correcta.

### Cloud Focused Penetration Testing

Aunque se superpone en gran medida con un penetration test convencional, una evaluación con un enfoque en la nube se beneficiará del conocimiento de alguien con experiencia en arquitectura y administración de la nube. A menudo puede ser tan simple como ayudar a articular al penetration tester qué es posible abusar con una información particular que se descubrió (como secretos o claves de algún tipo). Obviamente, cuando comienzas a introducir infraestructura menos convencional como contenedores y aplicaciones sin servidor, el enfoque para probar esos recursos requiere conocimientos muy específicos, probablemente una metodología y un conjunto de herramientas totalmente diferentes. Como el informe para estos tipos de evaluaciones es relativamente similar a los penetration tests convencionales, se mencionan en este contexto para que estés al tanto, pero los detalles técnicos sobre la prueba de estos recursos únicos están fuera del alcance de este curso.

### Comprehensive IoT Testing

Las plataformas IoT suelen tener tres componentes principales: red, nube y aplicación. Hay personas que están muy especializadas en cada uno de estos componentes que podrán proporcionar una evaluación mucho más completa juntas en lugar de depender de una sola persona con solo conocimientos básicos en cada área. Otro componente que puede necesitar ser probado es la capa de hardware, que se cubre a continuación. Similar a las pruebas

 en la nube, hay aspectos de estas pruebas que probablemente requerirán un conjunto de habilidades especializadas fuera del alcance de este curso, pero el diseño estándar del informe de penetration testing aún se presta bien para presentar este tipo de datos, no obstante.

---

## Web Application Penetration Testing

Dependiendo del alcance, este tipo de evaluación también puede considerarse una evaluación interdisciplinaria. Algunas evaluaciones de aplicaciones pueden centrarse solo en identificar y validar las vulnerabilidades en una aplicación con pruebas autenticadas basadas en roles, sin interés en evaluar el servidor subyacente. Otros pueden querer probar tanto la aplicación como la infraestructura con la intención de que el compromiso inicial sea a través de la aplicación web en sí (nuevamente, tal vez desde una perspectiva autenticada o basada en roles) y luego intentar moverse más allá de la aplicación para ver qué otros hosts y sistemas detrás de ella existen que puedan ser comprometidos. El último tipo de evaluación se beneficiaría de alguien con experiencia en desarrollo y pruebas de aplicaciones para el compromiso inicial y luego quizás un penetration tester enfocado en red para "living off the land" y moverse o escalar privilegios a través de Active Directory o algún otro medio más allá de la aplicación en sí.

---

## Hardware Penetration Testing

Este tipo de pruebas a menudo se realiza en dispositivos tipo IoT, pero se puede extender a probar la seguridad física de una laptop enviada por el cliente o un quiosco en el lugar o un cajero automático. Cada cliente tendrá un nivel de comodidad diferente con la profundidad de las pruebas aquí, por lo que es vital establecer las reglas de participación antes de que comience la evaluación, particularmente cuando se trata de pruebas destructivas. Si el cliente espera que su dispositivo regrese en una pieza y funcionando, probablemente no sea aconsejable intentar desoldar chips de la placa base o ataques similares.

---

## Draft Report

Es cada vez más común que los clientes esperen tener un diálogo e incorporar sus comentarios en un informe. Esto puede venir en muchas formas, ya sea que quieran agregar comentarios sobre cómo planean abordar cada hallazgo (respuesta de la administración), ajustar el lenguaje potencialmente inflamatorio o mover cosas a donde les convenga mejor. Por estas razones, es mejor planear enviar un borrador del informe primero, dar tiempo al cliente para que lo revise por su cuenta, y luego ofrecer un espacio de tiempo donde puedan revisarlo contigo para hacer preguntas, obtener aclaraciones o explicar lo que les gustaría ver. El cliente está pagando por el informe en última instancia, y debemos asegurarnos de que sea lo más completo y valioso para ellos posible. Algunos no comentarán en absoluto sobre el informe, mientras que otros pedirán cambios/adiciones significativas para ayudar a que se ajuste a sus necesidades, ya sea para hacerlo presentable a su junta directiva para obtener fondos adicionales o usar el informe como una entrada a su hoja de ruta de seguridad para realizar remediación y fortalecer su postura de seguridad.

---

## Final Report

Típicamente, después de revisar el informe con el cliente y confirmar que están satisfechos con él, puedes emitir el informe final con las modificaciones necesarias. Esto puede parecer un proceso frívolo, pero varias firmas de auditoría no aceptarán un borrador del informe para cumplir con sus obligaciones de cumplimiento, por lo que es importante desde la perspectiva del cliente.

### Post-Remediation Report

También es común que un cliente solicite que los hallazgos que descubriste durante la evaluación original sean probados nuevamente después de que hayan tenido la oportunidad de corregirlos. Esto es casi obligatorio para las organizaciones sujetas a un estándar de cumplimiento como PCI. No debes rehacer toda la evaluación para esta fase de la evaluación, sino que debes centrarte en retestear solo los hallazgos y solo los hosts afectados por esos hallazgos de la evaluación original. También quieres asegurarte de que hay un límite de tiempo en cuanto a cuánto tiempo después de la evaluación inicial realizamos pruebas de remediación. Aquí hay algunas cosas que podrían suceder si no lo haces.

- El cliente te pide que pruebes su remediación varios meses o incluso un año o más después, y el entorno ha cambiado tanto que es imposible obtener una comparación "manzanas con manzanas".
- Si revisas todo el entorno en busca de nuevos hosts afectados por un hallazgo dado, podrías descubrir nuevos hosts afectados y entrar en un bucle interminable de pruebas de remediación de los nuevos hosts que descubriste la última vez.
- Si realizas nuevos escaneos a gran escala como escaneos de vulnerabilidades, es probable que encuentres cosas que no estaban allí antes, y tu alcance se saldrá rápidamente de control.
- Si un cliente tiene un problema con la naturaleza de "instantánea" de este tipo de pruebas, podrías recomendar una herramienta de Breach and Attack Simulation (BAS) para ejecutar periódicamente esos escenarios y asegurarte de que no sigan apareciendo.

Si ocurre alguna de estas situaciones, debes esperar más escrutinio en torno a los niveles de gravedad y quizás presión para modificar cosas que no deben modificarse para ayudarles. En estas situaciones, tu respuesta debe estar cuidadosamente elaborada para ser clara de que no vas a cruzar límites éticos (pero ten cuidado de insinuar que te están pidiendo que hagas algo intencionalmente deshonesto, lo que indica que son deshonestos), pero también compadécete de su situación y ofrece algunas formas de salir de ella para ellos. Por ejemplo, si su preocupación es estar bajo el control de un auditor para solucionar algo en un tiempo que no tienen, es posible que no sepan que muchos auditores aceptarán un plan de remediación completamente documentado con una fecha límite razonable (y justificación de por qué no se puede completar más rápidamente) en lugar de remediar y cerrar el hallazgo dentro del período de examen. Esto te permite mantener tu integridad intacta, fomenta la sensación con el cliente de que realmente te importa su situación y les da un camino a seguir sin tener que volverse locos para hacerlo.

En estos casos, una forma de abordarlo podría ser tratarlo como una nueva evaluación. Si el cliente no está dispuesto, entonces probablemente querríamos retestear solo los hallazgos del informe original y señalar cuidadosamente en el informe el tiempo transcurrido desde la evaluación original, que esta es una verificación puntual para evaluar si SOLO las vulnerabilidades previamente reportadas afectan al host o hosts originalmente reportados y que es probable que el entorno del cliente haya cambiado significativamente, y no se realizó una nueva evaluación.

En términos de diseño de informes, algunas personas pueden preferir actualizar la evaluación original etiquetando los hosts afectados en cada hallazgo con un estado (por ejemplo, resuelto, no resuelto, parcial, etc.), mientras que otros pueden preferir emitir un nuevo informe completo que tenga algún contenido de comparación adicional y un resumen ejecutivo actualizado.

---

## Attestation Report

Algunos clientes solicitarán una `Attestation Letter` o `Attestation Report` que sea adecuada para sus proveedores o clientes que requieren evidencia de que se ha realizado un penetration test. La diferencia más significativa es que tu cliente no querrá entregar los detalles técnicos específicos de todos los hallazgos o credenciales u otra información secreta que pueda estar incluida a un tercero. Este documento puede derivarse del informe. Debe centrarse solo en la cantidad de hallazgos descubiertos, el enfoque tomado y comentarios generales sobre el entorno en sí. Este documento probablemente solo debe tener una o dos páginas.

---

## Other Deliverables

### Slide Deck

También se te puede solicitar preparar una presentación que se pueda dar en varios niveles diferentes. Tu audiencia puede ser técnica, o pueden ser más ejecutivos. El lenguaje y el enfoque deben ser tan diferentes en tu presentación ejecutiva como el resumen ejecutivo lo es de los detalles técnicos de los hallazgos en tu informe. Solo incluir gráficos y números pondrá a tu audiencia a dormir, por lo que es mejor estar preparado con algunas anécdotas de tu propia experiencia o tal vez algunos eventos recientes que se correlacionen con un vector de ataque o compromiso específico. Puntos extra si dicha historia está en la misma industria que tu cliente. El propósito de esto no es sembrar el miedo, y debes tener cuidado de no presentarlo de esa manera, pero ayudará a mantener la atención de tu audiencia. Hará que el riesgo sea lo suficientemente relacionable como para maximizar sus posibilidades de hacer algo al respecto.

### Spreadsheet of Findings

La hoja de cálculo de hallazgos debe ser bastante autoexplicativa. Estos son todos los campos en los hallazgos de tu informe, solo en un diseño tabular que el cliente puede usar para una clasificación más fácil y otras manipulaciones de datos. Esto también puede ayudarles a importar esos hallazgos en un sistema de tickets para fines de seguimiento interno. Este documento no debe incluir tu resumen ejecutivo o narrativas. Idealmente, aprende a usar tablas dinámicas (pivot tables) y utilízalas para crear algunos análisis interesantes que el cliente pueda encontrar interesantes. El objetivo más útil al hacer esto es clasificar los hallazgos por gravedad o categoría para ayudar a priorizar la remediación.

---

## Vulnerability Notifications

A veces, durante una evaluación, descubrimos una falla crítica que requiere que detengamos el trabajo e informemos a nuestros clientes sobre un problema para que puedan decidir si desean emitir una solución de emergencia o esperar hasta que finalice la evaluación.

### When to Draft One

Como mínimo, esto debe hacerse para cualquier hallazgo que sea directamente explotable que esté expuesto a internet y resulte en ejecución remota de código no autenticada o exposición de datos sensibles, o aproveche credenciales débiles/predeterminadas para lo mismo. Más allá de eso, las expectativas deben establecerse durante el proceso de inicio del proyecto. Algunos clientes pueden querer que se informen todos los hallazgos altos y críticos fuera de banda, independientemente de si son

 internos o externos. Algunas personas pueden necesitar también los medios. Por lo general, es mejor establecer una línea de base para ti, decirle al cliente qué esperar y dejar que pidan modificaciones al proceso si las necesitan.

### Contents

Debido a la naturaleza de estas notificaciones, es importante limitar la cantidad de contenido innecesario en estos documentos para que las personas técnicas puedan ir directamente a los detalles y comenzar a solucionar el problema. Por esta razón, probablemente sea mejor limitar esto al contenido típico que tienes en los detalles técnicos de tus hallazgos y proporcionar evidencia basada en herramientas para el hallazgo que el cliente pueda reproducir rápidamente si es necesario.

---

## Piecing it Together

Ahora que hemos cubierto los diversos tipos de evaluaciones y tipos de informes que se nos puede pedir crear para nuestros clientes, pasemos a hablar sobre los componentes de un informe.