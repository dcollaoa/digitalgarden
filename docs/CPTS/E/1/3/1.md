La sección `Findings` de nuestro informe es el "meollo". Aquí es donde mostramos lo que encontramos, cómo lo explotamos y proporcionamos al cliente orientación sobre cómo remediar los problemas. Cuantos más detalles podamos poner en cada hallazgo, mejor. Esto ayudará a los equipos técnicos a reproducir el hallazgo por sí mismos y luego a poder probar que su solución funcionó. Ser detallado en esta sección también ayudará a quien sea asignado para la evaluación posterior a la remediación si el cliente contrata a tu empresa para realizarla. Aunque a menudo tenemos hallazgos "predefinidos" en algún tipo de base de datos, es esencial adaptarlos al entorno de nuestro cliente para asegurarnos de no presentar mal nada.

---

## Breakdown of a Finding

Cada hallazgo debe tener el mismo tipo general de información que debe personalizarse según las circunstancias específicas de tu cliente. Si un hallazgo está escrito para adaptarse a varios escenarios o protocolos diferentes, la versión final debe ajustarse para referirse solo a las circunstancias particulares que identificaste. `"Default Credentials"` podría tener diferentes significados para el riesgo si afecta a una impresora DeskJet en comparación con el control HVAC del edificio u otra aplicación web de alto impacto. Como mínimo, la siguiente información debe incluirse para cada hallazgo:

- Descripción del hallazgo y qué plataforma(s) afecta la vulnerabilidad
- Impacto si el hallazgo no se resuelve
- Sistemas, redes, entornos o aplicaciones afectados
- Recomendación sobre cómo abordar el problema
- Enlaces de referencia con información adicional sobre el hallazgo y su resolución
- Pasos para reproducir el problema y la evidencia que recopilaste

Algunos campos adicionales y opcionales incluyen:

```
- CVE
- OWASP, MITRE IDs
- CVSS o similar
- Facilidad de explotación y probabilidad de ataque
- Cualquier otra información que pueda ayudar a aprender sobre y mitigar el ataque
```

---

## Showing Finding Reproduction Steps Adequately

Como se mencionó en la sección anterior sobre el Executive Summary, es importante recordar que, aunque tu punto de contacto puede ser razonablemente técnico, si no tiene una experiencia específica en penetration testing, hay una buena probabilidad de que no tenga idea de lo que está viendo. Puede que nunca haya oído hablar de la herramienta que usaste para explotar la vulnerabilidad, mucho menos entender qué es importante en el muro de texto que genera cuando se ejecuta el comando. Por esta razón, es crucial protegerte de dar cosas por sentadas y asumir que la gente sabe cómo llenar los vacíos por sí mismos. Si no haces esto correctamente, nuevamente, esto erosionará la efectividad de tu entregable, pero esta vez a los ojos de tu audiencia técnica. Algunos conceptos a considerar:

- Divide cada paso en su propia figura. Si realizas múltiples pasos en la misma figura, un lector no familiarizado con las herramientas que se están utilizando puede no entender lo que está sucediendo, y mucho menos tener una idea de cómo reproducirlo por sí mismo.
    
- Si se requiere configuración (por ejemplo, módulos de Metasploit), captura la configuración completa para que el lector pueda ver cómo debería ser la configuración del exploit antes de ejecutarlo. Crea una segunda figura que muestre lo que sucede cuando ejecutas el exploit.
    
- Escribe una narrativa entre figuras que describa lo que está sucediendo y lo que estás pensando en ese momento de la evaluación. No trates de explicar lo que está sucediendo en la figura con el pie de foto y tener un montón de figuras consecutivas.
    
- Después de realizar tu demostración utilizando tu toolkit preferido, ofrece herramientas alternativas que puedan utilizarse para validar el hallazgo si existen (solo menciona la herramienta y proporciona un enlace de referencia, no hagas el exploit dos veces con más de una herramienta).
    

Tu objetivo principal debe ser presentar la evidencia de una manera que sea comprensible y procesable para el cliente. Piensa en cómo el cliente utilizará la información que estás presentando. Si estás mostrando una vulnerabilidad en una aplicación web, una captura de pantalla de Burp no es la mejor manera de presentar esta información si estás creando tus propias solicitudes web. El cliente probablemente querrá copiar/pegar el payload de tus pruebas para recrearlo, y no pueden hacer eso si es solo una captura de pantalla.

Otra cosa crítica a considerar es si tu evidencia es completamente y absolutamente defendible. Por ejemplo, si estás tratando de demostrar que la información se transmite en texto claro debido al uso de autenticación básica en una aplicación web, no es suficiente solo capturar la ventana emergente del prompt de inicio de sesión. Eso muestra que la autenticación básica está en su lugar, pero no ofrece prueba de que la información se está transmitiendo en texto claro. En este caso, mostrar el prompt de inicio de sesión con algunas credenciales falsas ingresadas y las credenciales en texto claro en una captura de paquetes de Wireshark de la solicitud de autenticación en formato legible por humanos no deja espacio para el debate. Del mismo modo, si estás tratando de demostrar la presencia de una vulnerabilidad en una aplicación web en particular o en algo más con una GUI (como RDP), es importante capturar ya sea la URL en la barra de direcciones o la salida de un comando `ifconfig` o `ipconfig` para demostrar que está en el host del cliente y no en alguna imagen aleatoria que descargaste de Google. Además, si estás capturando tu navegador, apaga tu barra de marcadores y desactiva cualquier extensión de navegador no profesional o dedica un navegador web específico para tus pruebas.

A continuación se muestra un ejemplo de cómo podríamos mostrar los pasos para capturar un hash utilizando la herramienta Responder y crackearlo offline utilizando Hashcat. Aunque no es 100% necesario, puede ser bueno listar herramientas alternativas como hicimos con este hallazgo. El cliente puede estar trabajando desde una máquina Windows y encontrar un script de PowerShell o un ejecutable más fácil de usar o puede estar más familiarizado con otro conjunto de herramientas. Ten en cuenta que también redactamos el hash y las contraseñas en texto claro, ya que este informe podría ser pasado a muchas audiencias diferentes, por lo que puede ser mejor redactar credenciales siempre que sea posible.

![image](https://academy.hackthebox.com/storage/modules/162/evidence_example.png)

---

## Effective Remediation Recommendations

#### Example 1

- `Bad`: Reconfigure your registry settings to harden against X.
    
- `Good`: To fully remediate this finding, the following registry hives should be updated with the specified values. Note that changes to critical components like the registry should be approached with caution and tested in a small group prior to making large-scale changes.
    
    - `[list the full path to the affected registry hives]`
        - Change value X to value Y

#### Rationale

Aunque el ejemplo "malo" es al menos algo útil, es bastante perezoso, y estás desperdiciando una oportunidad de aprendizaje. Una vez más, el lector de este informe puede no tener la profundidad de experiencia en Windows como tú, y darle una recomendación que requerirá horas de trabajo para que descubra cómo hacerlo solo va a frustrarlo. Haz tu tarea y sé lo más específico posible. Hacer esto tiene los siguientes beneficios:

- Aprendes más de esta manera y estarás mucho más cómodo respondiendo preguntas durante la revisión del informe. Esto reforzará la confianza del cliente en ti y será conocimiento que podrás aprovechar en futuras evaluaciones y para ayudar a nivelar tu equipo.
    
- El cliente apreciará que hagas la investigación por él y describas específicamente lo que debe hacerse para que pueda ser lo más eficiente posible. Esto aumentará la probabilidad de que te pidan hacer futuras evaluaciones y te recomienden a ti y a tu equipo a sus amigos.
    

También vale la pena señalar que el ejemplo "bueno" incluye una advertencia de que cambiar algo tan importante como el registro conlleva su propio conjunto de riesgos y debe realizarse con precaución. Nuevamente, esto indica al cliente que tienes sus mejores intereses en mente y que realmente quieres que tengan éxito. Para bien o para mal, habrá clientes que harán ciegamente lo que les digas y no dudarán en intentar responsabilizarte si hacerlo termina rompiendo algo.

#### Example 2

- `Bad`: Implement `[some commercial tool that costs a fortune]` to address this finding.
    
- `Good`: There are different approaches to addressing this finding. `[Name of the affected software vendor]` has published a workaround as an interim solution. For the sake of brevity, a link to the walkthrough has been provided in the reference links below. Alternatively, there are commercial tools available that would make it possible to disable the vulnerable functionality in the affected software altogether, but these tools may be cost-prohibitive.
    

#### Rationale

El ejemplo "malo" no da al cliente ninguna forma de remediar este problema sin gastar mucho dinero que puede no tener. Aunque la herramienta comercial puede ser la solución más fácil con diferencia, muchos clientes no tendrán el presupuesto para hacerlo y necesitan una solución alternativa. La solución alternativa puede ser un parche temporal o extraordinariamente engorroso, o ambos, pero al menos comprará al cliente algo de tiempo hasta que el proveedor haya lanzado una solución oficial.

---

## Selecting Quality References

Cada hallazgo debe incluir una o más referencias externas para una lectura adicional sobre una vulnerabilidad o configuración incorrecta en particular. Algunos criterios que mejoran la utilidad de una referencia:

- Una fuente independiente del proveedor es útil. Obviamente, si encuentras una vulnerabilidad en un ASA, un enlace de referencia de Cisco tiene sentido, pero no me apoyaría en ellos para una descripción detallada sobre cualquier cosa fuera de networking. Si referencias un artículo escrito por un proveedor de

 productos, es probable que el enfoque del artículo sea decirle al lector cómo su producto puede ayudar cuando todo lo que el lector quiere es saber cómo solucionarlo por sí mismo.

- Una descripción detallada o explicación del hallazgo y cualquier solución provisional o mitigación recomendada es preferible. No elijas artículos detrás de un muro de pago o algo donde solo obtienes parte de lo que necesitas sin pagar.

- Usa artículos que vayan al grano rápidamente. Esto no es un sitio web de recetas, y a nadie le importa cuántas veces tu abuela solía hacer esas galletas. Tenemos problemas que resolver, y hacer que alguien tenga que escarbar en todo el documento NIST 800-53 o un RFC es más molesto que útil.
    
- Elige fuentes que tengan sitios web limpios y no te hagan sentir que un montón de mineros de criptomonedas están funcionando en segundo plano o que aparecen anuncios por todas partes.
    
- Si es posible, escribe algo de tu propio material fuente y blog sobre ello. La investigación te ayudará a explicar el impacto del hallazgo a tus clientes, y aunque la comunidad infosec es bastante útil, sería preferible no enviar a tus clientes al sitio web de un competidor.
    

---

## Example Findings

A continuación se muestran algunos hallazgos de ejemplo. Los dos primeros son ejemplos de problemas que pueden ser descubiertos durante un Internal Penetration Test. Como puedes ver, cada hallazgo incluye todos los elementos clave: una descripción detallada para explicar lo que está sucediendo, el impacto en el entorno si el hallazgo queda sin resolver, los hosts afectados por el problema (o todo el dominio), consejo de remediación que es genérico, no recomienda herramientas específicas de proveedores y ofrece varias opciones para la remediación. Finalmente, los enlaces de referencia son de fuentes bien conocidas y de buena reputación que probablemente no se eliminarán en cualquier momento como puede suceder con un blog personal.

Una nota sobre el formato: Esto podría ser potencialmente un tema muy debatido. Los hallazgos de ejemplo aquí se han presentado en un formato tabular, pero si alguna vez has trabajado en Word o intentado automatizar parte de la generación de informes, sabes que las tablas pueden ser una pesadilla para tratar. Por esta razón, otros optan por separar las secciones de sus hallazgos con diferentes niveles de encabezados. Cualquiera de estos enfoques es aceptable porque lo que es importante es si tu mensaje llega al lector y lo fácil que es identificar las señales visuales para cuando termina un hallazgo y comienza otro; la legibilidad es primordial. Si puedes lograr esto, los colores, el diseño, el orden e incluso los nombres de las secciones pueden ajustarse.

#### Weak Kerberos Authentication (“Kerberoasting”)

![image](https://academy.hackthebox.com/storage/modules/162/kbroast.png)

#### Tomcat Manager Weak/Default Credentials

![image](https://academy.hackthebox.com/storage/modules/162/tomcat_finding.png)

#### Poorly Written Finding

A continuación se muestra un ejemplo de un hallazgo mal escrito que tiene varios problemas:

- El formato es descuidado con el enlace CWE
- No se ha llenado la puntuación CVSS (no es obligatorio, pero si tu plantilla de informe lo usa, deberías llenarlo)
- La Descripción no explica claramente el problema o la causa raíz
- El impacto en la seguridad es vago y genérico
- La sección de Remediación no es clara ni procesable

Si estoy leyendo este informe, puedo ver que este hallazgo es malo (porque está en rojo), pero ¿por qué me importa? ¿Qué hago al respecto? Cada hallazgo debe presentar el problema en detalle y educar al lector sobre el problema en cuestión (es muy probable que nunca hayan oído hablar de Kerberoasting u otro ataque). Articula claramente el riesgo de seguridad y el `por qué` necesita ser remediado y algunas recomendaciones de remediación accionables.

![image](https://academy.hackthebox.com/storage/modules/162/kbroast_weak.png)

---

## Hands-On Practice

El target VM que se puede lanzar en esta sección tiene una copia de la herramienta de informes [WriteHat](https://github.com/blacklanternsecurity/writehat) ejecutándose. Esta es una herramienta útil para construir una base de datos de hallazgos y generar informes personalizados. Aunque no respaldamos ninguna herramienta específica en este módulo, muchas herramientas de informes son similares, por lo que jugar con WriteHat te dará una buena idea de cómo funcionan este tipo de herramientas. Practica agregar hallazgos a la base de datos, construir y generar un informe, etc. Prellenamos la base de datos de hallazgos con algunas categorías comunes de hallazgos y algunos de los hallazgos incluidos en el informe de muestra adjunto a este módulo. Experimenta con él tanto como quieras y practica las habilidades enseñadas en esta sección. Ten en cuenta que cualquier cosa que ingreses en la herramienta no se guardará una vez que el target expire, por lo que si escribes algún hallazgo de práctica, asegúrate de mantener una copia local. Esta herramienta también será útil para el laboratorio guiado al final de este módulo.

Una vez que el target se inicie, navega a `https://< target IP >` y inicia sesión con las credenciales `htb-student:HTB_@cademy_stdnt!`.

![image](https://academy.hackthebox.com/storage/modules/162/writehat.png)

Practica escribir hallazgos y explorar la herramienta. Incluso puede que te guste lo suficiente como para usarlo como parte de tu flujo de trabajo. Una idea sería instalar una copia localmente y practicar escribir hallazgos para los problemas que descubras en los laboratorios del módulo Academy o en cajas/laboratorios en la plataforma principal de HTB.

---

## Nearly There

Ahora que hemos cubierto cómo mantenerse organizado durante un penetration test, tipos de informes, los componentes estándar de un informe y cómo escribir un hallazgo, tenemos algunos consejos/trucos de informes para compartir contigo de nuestra experiencia colectiva en el campo.