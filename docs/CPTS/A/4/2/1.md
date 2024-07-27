Hay varias formas de calificar o calcular las clasificaciones de severidad de las vulnerabilidades. El [Common Vulnerability Scoring System (CVSS)](https://www.first.org/cvss/) es un estándar de la industria para realizar estos cálculos. Muchas herramientas de escaneo aplican estas puntuaciones a cada hallazgo como parte de los resultados del escaneo, pero es importante que entendamos cómo se derivan estas puntuaciones en caso de que alguna vez necesitemos calcular una manualmente o justificar la puntuación aplicada a una vulnerabilidad dada. El CVSS a menudo se utiliza junto con el denominado [Microsoft DREAD](https://en.wikipedia.org/wiki/DREAD_(risk_assessment_model)). `DREAD` es un sistema de evaluación de riesgos desarrollado por Microsoft para ayudar a los profesionales de la seguridad informática a evaluar la gravedad de las amenazas y vulnerabilidades de seguridad. Se utiliza para realizar un análisis de riesgos utilizando una escala de 10 puntos para evaluar la gravedad de las amenazas y vulnerabilidades de seguridad. Con esto, calculamos el riesgo de una amenaza o vulnerabilidad basándonos en cinco factores principales:

- Damage Potential
- Reproducibility
- Exploitability
- Affected Users
- Discoverability

El modelo es esencial para la estrategia de seguridad de Microsoft y se utiliza para monitorear, evaluar y responder a amenazas y vulnerabilidades de seguridad en los productos de Microsoft. También sirve como referencia para que los profesionales de seguridad informática y gerentes realicen su evaluación de riesgos y priorización de amenazas y vulnerabilidades de seguridad.

---

## Risk Scoring

El sistema CVSS ayuda a categorizar el riesgo asociado con un problema y permite a las organizaciones priorizar problemas en función de la calificación. La puntuación CVSS consiste en la `exploitability and impact` de un problema. Las mediciones de `exploitability` consisten en `access vector`, `access complexity` y `authentication`. Las métricas de `impact` consisten en la `CIA triad`, incluyendo `confidentiality`, `integrity` y `availability`.

![metricgroup](https://academy.hackthebox.com/storage/modules/108/graphics/VulnerabilityAssessment_Diagram_08.png) _Adaptado del gráfico original encontrado [aquí](https://www.first.org/cvss/v3-1/media/MetricGroups.svg)._

---

## Base Metric Group

El grupo de métricas base de CVSS representa las características de la vulnerabilidad y consiste en métricas de `exploitability` y métricas de `impact`.

### Exploitability Metrics

Las métricas de Exploitability son una forma de evaluar los medios técnicos necesarios para explotar el problema utilizando las siguientes métricas:

- Attack Vector
- Attack Complexity
- Privileges Required
- User Interaction

### Impact Metrics

Las métricas de Impact representan las repercusiones de explotar con éxito un problema y lo que se ve afectado en un entorno, y se basan en la triada CIA. La triada CIA es un acrónimo de `Confidentiality`, `Integrity` y `Availability`.

![CIA Triad](https://academy.hackthebox.com/storage/modules/108/graphics/cia_triad.png)

`Confidentiality Impact` se relaciona con asegurar la información y garantizar que solo las personas autorizadas tengan acceso. Por ejemplo, un valor de severidad alto sería en el caso de que un atacante robara contraseñas o claves de cifrado. Un valor de severidad bajo se relacionaría con un atacante tomando información que puede no ser un activo vital para una organización.

`Integrity Impact` se relaciona con que la información no se cambie ni se manipule para mantener la precisión. Por ejemplo, una severidad alta sería si un atacante modificara archivos comerciales cruciales en el entorno de una organización. Un valor de severidad bajo sería si un atacante no pudiera controlar específicamente la cantidad de archivos cambiados o modificados.

`Availability Impact` se relaciona con tener información disponible para los requisitos comerciales. Por ejemplo, un valor alto sería si un atacante causara que un entorno fuera completamente inaccesible para el negocio. Un valor bajo sería si un atacante no pudiera denegar completamente el acceso a los activos comerciales y los usuarios aún pudieran acceder a algunos activos de la organización.

---

## Temporal Metric Group

El `Temporal Metric Group` detalla la disponibilidad de exploits o parches con respecto al problema.

### Exploit Code Maturity

La métrica `Exploit Code Maturity` representa la probabilidad de que se explote un problema en función de la facilidad de las técnicas de explotación. Hay varios valores métricos asociados con esta métrica, incluyendo `Not Defined`, `High`, `Functional`, `Proof-of-Concept` y `Unproven`.

Un valor de 'Not Defined' se relaciona con omitir esta métrica en particular. Un valor de 'High' representa un exploit que funciona consistentemente para el problema y es fácilmente identificable con herramientas automatizadas. Un valor de 'Functional' indica que hay código de exploit disponible para el público. Un valor de 'Proof-of-Concept' demuestra que hay código de exploit PoC disponible, pero que requeriría cambios para que un atacante explote el problema con éxito.

### Remediation Level

El `Remediation level` se utiliza para identificar la priorización de una vulnerabilidad. Los valores métricos asociados con esta métrica incluyen `Not Defined`, `Unavailable`, `Workaround`, `Temporary Fix` y `Official Fix`.

Un valor de 'Not Defined' se relaciona con omitir esta métrica en particular. Un valor de 'Unavailable' indica que no hay parche disponible para la vulnerabilidad. Un valor de 'Workaround' indica una solución no oficial lanzada hasta que el proveedor proporcione un parche oficial. Un valor de 'Temporary Fix' significa que un proveedor oficial ha proporcionado una solución temporal pero aún no ha lanzado un parche para el problema. Un valor de 'Official Fix' indica que un proveedor ha lanzado un parche oficial para el problema al público.

### Report Confidence

`Report Confidence` representa la validación de la vulnerabilidad y cuán precisos son los detalles técnicos del problema. Los valores métricos asociados con esta métrica incluyen `Not Defined`, `Confirmed`, `Reasonable` y `Unknown`.

Un valor de 'Not Defined' se relaciona con omitir esta métrica en particular. Un valor de 'Confirmed' indica que hay varias fuentes con información detallada que confirma la vulnerabilidad. Un valor de 'Reasonable' indica que las fuentes han publicado información sobre la vulnerabilidad. Sin embargo, no hay una confianza completa de que alguien lograría el mismo resultado debido a la falta de detalles para reproducir el exploit para el problema.

---

## Environmental Metric Group

El grupo de métricas ambientales representa la importancia de la vulnerabilidad para una organización, teniendo en cuenta la triada CIA.

### Modified Base Metrics

Las `Modified Base metrics` representan las métricas que pueden modificarse si la organización afectada considera un riesgo mayor en Confidentiality, Integrity y Availability para su organización. Los valores asociados con esta métrica son `Not Defined`, `High`, `Medium` y `Low`.

Un valor de 'Not Defined' indicaría omitir esta métrica. Un valor de 'High' significaría que uno de los elementos de la triada CIA tendría efectos astronómicos en la organización y sus clientes. Un valor de 'Medium' indicaría que uno de los elementos de la triada CIA tendría efectos significativos en la organización y sus clientes. Un valor de 'Low' significaría que uno de los elementos de la triada CIA tendría efectos mínimos en la organización y sus clientes.

---

## Calculating CVSS Severity

El cálculo de una puntuación CVSS v3.1 tiene en cuenta todas las métricas discutidas en esta sección. La National Vulnerability Database tiene un calculador disponible para el público [aquí](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator).

### CVSS Calculation Example

Por ejemplo, para la Vulnerabilidad de Ejecución de Código Remoto del Windows Print Spooler, la métrica base de CVSS es 8.8. Puedes consultar los valores de cada métrica [aquí](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527).

---

## Next Steps

A continuación, discutiremos cómo se clasifican las vulnerabilidades de una manera estándar que las herramientas de escaneo pueden usar para incluir una referencia externa a la vulnerabilidad particular.