## Open Vulnerability Assessment Language (OVAL)

[Open Vulnerability Assessment Language (OVAL)](https://oval.mitre.org/) es un estándar internacional de seguridad de la información disponible públicamente que se utiliza para evaluar y detallar el estado actual y los problemas del sistema. OVAL también cuenta con el apoyo de la oficina de Cybersecurity and Communications del Departamento de Seguridad Nacional de EE.UU. OVAL proporciona un lenguaje para comprender la codificación de atributos del sistema y varios repositorios de contenido compartidos dentro de la comunidad de seguridad. El repositorio de OVAL tiene más de 7000+ definiciones para uso público. Además, OVAL también es utilizado por el [Security Content Automation Protocol (SCAP)](https://csrc.nist.gov/projects/security-content-automation-protocol) del Instituto Nacional de Estándares y Tecnología (NIST) de EE.UU., que reúne ideas de la comunidad para automatizar la gestión de vulnerabilidades, la medición y garantizar que los sistemas cumplan con las políticas de cumplimiento.

### OVAL Process

![oval](https://academy.hackthebox.com/storage/modules/108/graphics/VulnerabilityAssessment_Diagram_05.png) _Adaptado del gráfico original encontrado [aquí](https://oval.mitre.org/documents/docs-05/extras/0505Martin_f3.gif)._

El objetivo del lenguaje OVAL es tener una estructura de tres pasos durante el proceso de evaluación que consiste en:

- Identificar las configuraciones del sistema para pruebas
- Evaluar el estado actual del sistema
- Divulgar la información en un informe

La información puede describirse en varios tipos de estados, incluidos: `Vulnerable`, `Non-compliant`, `Installed Asset` y `Patched`.

### OVAL Definitions

Las definiciones de OVAL se registran en un formato XML para descubrir cualquier vulnerabilidad de software, configuraciones incorrectas, programas y información adicional del sistema, eliminando la necesidad de explotar un sistema. Al tener la capacidad de identificar problemas sin explotar directamente el problema, una organización puede correlacionar qué sistemas necesitan ser parchados en una red.

Las cuatro clases principales de definiciones de OVAL consisten en:

- `OVAL Vulnerability Definitions`: Identifica vulnerabilidades del sistema
- `OVAL Compliance Definitions`: Identifica si las configuraciones actuales del sistema cumplen con los requisitos de la política del sistema
- `OVAL Inventory Definitions`: Evalúa un sistema para ver si un software específico está presente
- `OVAL Patch Definitions`: Identifica si un sistema tiene el parche adecuado

Además, el `OVAL ID Format` consiste en un formato único que consiste en "oval:Organization Domain Name:ID Type:ID Value". El `ID Type` puede caer en varias categorías, incluidas: definición (`def`), objeto (`obj`), estado (`ste`) y variable (`var`). Un ejemplo de un identificador único sería `oval:org.mitre.oval:obj:1116`.

Escáneres como Nessus tienen la capacidad de usar OVAL para configurar plantillas de escaneo de cumplimiento de seguridad.

---

## Common Vulnerabilities and Exposures (CVE)

[Common Vulnerabilities and Exposures (CVE)](https://cve.mitre.org/) es un catálogo de problemas de seguridad disponible públicamente patrocinado por el Departamento de Seguridad Nacional de EE.UU. (DHS). Cada problema de seguridad tiene un número de identificación CVE único asignado por la CVE Numbering Authority (CNA). El propósito de crear un número de identificación CVE único es crear una estandarización para una vulnerabilidad o exposición a medida que un investigador la identifica. Un CVE consiste en información crítica sobre una vulnerabilidad o exposición, incluida una descripción y referencias sobre el problema. La información en un CVE permite al equipo de TI de una organización comprender cuán perjudicial podría ser un problema para su entorno.

El siguiente gráfico explica cómo se puede asignar un ID de CVE a una vulnerabilidad. Cualquier vulnerabilidad asignada a un CVE debe ser reparable de forma independiente, afectar solo a una base de código y ser reconocida y documentada por el proveedor relevante.

![qualifications](https://academy.hackthebox.com/storage/modules/108/cve/VulnerabilityAssessment_Diagram_01.png) _Adaptado del gráfico original [aquí](https://www.balbix.com/app/uploads/what-is-a-CVE-1024x655.png)._

---

## Stages of Obtaining a CVE

### Stage 1: Identify if CVE is Required and Relevant

Identificar si el problema encontrado es una vulnerabilidad. Según el equipo de CVE, "Una vulnerabilidad en el contexto del Programa CVE se indica por un código que puede ser explotado, resultando en un impacto negativo en la confidencialidad, integridad O disponibilidad, y que requiere un cambio en el código, cambio en la especificación o la eliminación de la especificación para mitigar o abordar". Además, se debe verificar que no haya un ID de CVE ya en la base de datos de CVE.

### Stage 2: Reach Out to Affected Product Vendor

Un investigador debe asegurarse de haber hecho un esfuerzo de buena fe para contactar directamente a un proveedor. Los investigadores pueden consultar los [Documentos sobre Prácticas de Divulgación](https://cve.mitre.org/cve/researcher_reservation_guidelines#appendix#a) de CVE para obtener información adicional.

### Stage 3: Identify if Request Should Be For Vendor CNA or Third Party CNA

Si una empresa es parte de los CNA participantes, pueden asignar un ID de CVE para uno de sus productos. Si el problema es para un CNA participante, los investigadores pueden contactar a la organización CNA apropiada [aquí](https://cve.mitre.org/cve/request_id.html). Si el proveedor no es un CNA participante, un investigador debe intentar contactar al coordinador de terceros del proveedor.

### Stage 4: Requesting CVE ID Through CVE Web Form

El equipo de CVE tiene un formulario que se puede llenar en línea [aquí](https://cveform.mitre.org/) si los métodos anteriores no funcionan para las solicitudes de CVE.

### Stage 5: Confirmation of CVE Form

Al enviar el formulario web de CVE mencionado en el Stage 4, un individuo recibirá un correo electrónico de confirmación. El equipo de CVE contactará al solicitante si se requiere información adicional.

### Stage 6: Receival of CVE ID

Una vez aprobado, el equipo de CVE notificará al solicitante de un ID de CVE si se confirma la vulnerabilidad del producto afectado. Tenga en cuenta que el ID de CVE aún no es público en esta etapa.

### Stage 7: Public Disclosure of CVE ID

Los IDs de CVE pueden ser anunciados al público tan pronto como los proveedores y partes apropiadas estén al tanto del problema para evitar la duplicación de IDs de CVE. Esta etapa asegura que todas las partes asociadas estén al tanto del problema antes de ser divulgado públicamente.

### Stage 8: Announcing the CVE

El equipo de CVE solicita a los investigadores que están compartiendo múltiples CVE que se aseguren de que cada CVE indique las diferentes vulnerabilidades. Se puede encontrar información adicional [aquí](https://cve.mitre.org/cve/researcher_reservation_guidelines).

### Stage 9: Providing Information to The CVE Team

En esta etapa, el equipo de CVE solicita que el investigador ayude a proporcionar información adicional que se utilizará en la lista oficial de CVE en el sitio web. La [Base de Datos Nacional de Vulnerabilidades (NVD)](https://nvd.nist.gov/) de EE.UU. también mantiene esta información en línea en su base de datos.

---

## Responsible Disclosure

Los investigadores de seguridad y consultores constantemente consultan la base de datos de CVE ya que consiste en miles de vulnerabilidades que podrían ser aprovechadas para la explotación. Además, hay momentos en que los individuos pueden encontrar un problema que nunca han visto en el mundo real o que nunca se ha divulgado mientras investigan un software o programa específico.

La divulgación responsable es esencial en la comunidad de seguridad porque permite que una organización o investigador trabaje directamente con un proveedor proporcionándoles los detalles del problema primero para asegurar que haya un parche disponible antes del anuncio de la vulnerabilidad al mundo. Si un problema no se divulga de manera responsable a un proveedor, los actores de amenazas reales pueden aprovechar los problemas para uso criminal, también conocido como `zero day` o `0-day`.

---

## Examples

### CVE-2020-5902

[CVE-2020-5902](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-5902) es una vulnerabilidad de ejecución remota de código no autenticada en la Interfaz de Usuario de Gestión de Tráfico (TMUI) de BIG-IP. El problema es explotable cuando TMUI está disponible a través del puerto de gestión de BIG-IP y conduce a una toma de control completa del sistema, ya que un atacante podría ejecutar código, editar archivos y habilitar o deshabilitar servicios en el host remoto.

### CVE-2021-34527

[CVE-2021-34527](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34527), también conocido como PrintNightmare, es una vulnerabilidad de ejecución remota de código dentro del servicio de Windows Print Spooler. El servicio de Windows Print Spooler puede ser abusado debido a que el servicio maneja incorrectamente las operaciones de archivos de privilegios. El problema requiere que un usuario esté autenticado, pero permite la toma de control completa de un sistema desde la ejecución de código remoto

 o local. El problema es extremadamente peligroso ya que permite a un atacante controlar completamente un dominio, explotando servidores (incluyendo controladores de dominio) y estaciones de trabajo.

---

## Getting Hands-on

Ahora que hemos definido términos clave, discutido tipos de evaluación, puntuación de vulnerabilidades y divulgación, pasemos a familiarizarnos con dos herramientas populares de escaneo de vulnerabilidades: Nessus y OpenVAS.