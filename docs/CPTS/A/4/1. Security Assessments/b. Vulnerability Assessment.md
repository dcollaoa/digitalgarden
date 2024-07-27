Un `Vulnerability Assessment` tiene como objetivo identificar y categorizar los riesgos relacionados con debilidades de seguridad en los activos dentro de un entorno. Es importante notar que `hay poca o ninguna explotación manual durante una evaluación de vulnerabilidades`. Una evaluación de vulnerabilidades también proporciona pasos de remediación para solucionar los problemas.

El propósito de un `Vulnerability Assessment` es comprender, identificar y categorizar el riesgo de los problemas más evidentes presentes en un entorno sin realmente explotarlos para obtener un acceso adicional. Dependiendo del alcance de la evaluación, algunos clientes pueden pedirnos validar tantas vulnerabilidades como sea posible realizando una explotación mínimamente invasiva para confirmar los hallazgos del escáner y descartar falsos positivos. Otros clientes solicitarán un informe de todos los hallazgos identificados por el escáner. Como con cualquier evaluación, es esencial clarificar el alcance y la intención de la evaluación de vulnerabilidades antes de comenzar. La gestión de vulnerabilidades es vital para ayudar a las organizaciones a identificar los puntos débiles en sus activos, comprender el nivel de riesgo y calcular y priorizar los esfuerzos de remediación.

También es importante notar que las organizaciones siempre deben probar parches sustanciales antes de implementarlos en su entorno para evitar interrupciones.

---

## Metodología

A continuación se muestra una metodología de evaluación de vulnerabilidades de muestra que la mayoría de las organizaciones podrían seguir y encontrar éxito. Las metodologías pueden variar ligeramente de una organización a otra, pero este diagrama cubre los pasos principales, desde la identificación de activos hasta la creación de un plan de remediación.  
![process](https://academy.hackthebox.com/storage/modules/108/graphics/VulnerabilityAssessment_Diagram_06a.png)  
_Adaptado del gráfico original encontrado [aquí](https://purplesec.us/wp-content/uploads/2019/07/8-steps-to-performing-a-network-vulnerability-assessment-infographic.png)._

---

## Entendiendo los Términos Clave

Antes de continuar, identifiquemos algunos términos clave que cualquier profesional de TI o Infosec debe comprender y ser capaz de explicar claramente.

### Vulnerability

Una `Vulnerability` es una debilidad o error en el entorno de una organización, incluidas aplicaciones, redes e infraestructura, que abre la posibilidad de amenazas de actores externos. Las vulnerabilidades pueden registrarse a través de la base de datos de [Common Vulnerability Exposure de MITRE](https://cve.mitre.org/) y recibir una puntuación de [Common Vulnerability Scoring System (CVSS)](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator) para determinar la severidad. Este sistema de puntuación se usa frecuentemente como estándar para que las empresas y gobiernos calculen puntuaciones de severidad precisas y consistentes para las vulnerabilidades de sus sistemas. Puntuando las vulnerabilidades de esta manera se ayuda a priorizar los recursos y determinar cómo responder a una amenaza dada. Las puntuaciones se calculan usando métricas como el tipo de vector de ataque (network, adjacent, local, physical), la complejidad del ataque, los privilegios requeridos, si el ataque requiere o no interacción del usuario y el impacto de una explotación exitosa en la confidencialidad, integridad y disponibilidad de los datos de una organización. Las puntuaciones pueden variar de 0 a 10, dependiendo de estas métricas.

![Threat + Vulnerability = Risk](https://academy.hackthebox.com/storage/modules/108/graphics/threat_vulnerability_risk.png)

Por ejemplo, la inyección SQL se considera una vulnerabilidad ya que un atacante podría aprovechar consultas para extraer datos de la base de datos de una organización. Este ataque tendría una puntuación CVSS más alta si se pudiera realizar sin autenticación a través de internet que si un atacante necesitara acceso autenticado a la red interna y autenticación separada a la aplicación objetivo. Este tipo de cosas deben considerarse para todas las vulnerabilidades que encontremos.

### Threat

Una `Threat` es un proceso que amplifica el potencial de un evento adverso, como un actor de amenazas explotando una vulnerabilidad. Algunas vulnerabilidades generan más preocupaciones de amenaza que otras debido a la probabilidad de que la vulnerabilidad sea explotada. Por ejemplo, cuanto mayor sea la recompensa del resultado y la facilidad de explotación, más probable es que el problema sea explotado por actores de amenazas.

### Exploit

Un `Exploit` es cualquier código o recurso que puede usarse para aprovechar una debilidad de un activo. Muchos exploits están disponibles a través de plataformas de código abierto como [Exploit-db](https://exploit-db.com/) o [la Base de Datos de Vulnerabilidades y Explotaciones de Rapid7](https://www.rapid7.com/db/). A menudo también veremos código de exploit alojado en sitios como GitHub y GitLab.

### Risk

`Risk` es la posibilidad de que los activos o datos sean dañados o destruidos por actores de amenazas.

![What is Risk?](https://academy.hackthebox.com/storage/modules/108/graphics/whatisrisk.png)

Para diferenciar los tres, podemos pensar en ello de la siguiente manera:

- `Risk`: algo malo que podría pasar
- `Threat`: algo malo que está pasando
- `Vulnerabilities`: debilidades que podrían llevar a una amenaza

Las vulnerabilidades, amenazas y exploits juegan un papel en la medición del nivel de riesgo en las debilidades al determinar la probabilidad y el impacto. Por ejemplo, las vulnerabilidades que tienen código de exploit confiable y es probable que se usen para obtener acceso a la red de una organización aumentarían significativamente el riesgo de un problema debido al impacto. Si un atacante tuviera acceso a la red interna, podría potencialmente ver, editar o eliminar documentos sensibles cruciales para las operaciones comerciales. Podemos usar una matriz de riesgo cualitativa para medir el riesgo basado en la probabilidad y el impacto con la tabla que se muestra a continuación.

![risk](https://academy.hackthebox.com/storage/modules/108/graphics/VulnerabilityAssessment_Diagram_07.png)

En este ejemplo, podemos ver que una vulnerabilidad con una baja probabilidad de ocurrir y bajo impacto tendría el nivel de riesgo más bajo, mientras que una vulnerabilidad con alta probabilidad de ser explotada y el mayor impacto en una organización representaría el riesgo más alto y se querría priorizar para remediación.

---

## Asset Management

Cuando una organización de cualquier tipo, en cualquier industria y de cualquier tamaño necesita planificar su estrategia de ciberseguridad, debe comenzar creando un inventario de sus `data assets`. ¡Si quieres proteger algo, primero debes saber qué estás protegiendo! Una vez que los activos han sido inventariados, entonces puedes comenzar el proceso de `asset management`. Este es un concepto clave en la seguridad defensiva.

### Asset Inventory

El `Asset inventory` es un componente crítico de la gestión de vulnerabilidades. Una organización necesita comprender qué activos están en su red para proporcionar la protección adecuada y configurar defensas apropiadas. El inventario de activos debe incluir tecnología de la información, tecnología operativa, activos físicos, software, móviles y de desarrollo. Las organizaciones pueden utilizar herramientas de gestión de activos para realizar un seguimiento de los activos. Los activos deben tener clasificaciones de datos para garantizar una seguridad y controles de acceso adecuados.

### Application and System Inventory

Una organización debe crear un inventario completo y exhaustivo de activos de datos para una gestión adecuada de activos para la seguridad defensiva. Los activos de datos incluyen:

- Todos los datos almacenados en las instalaciones. HDDs y SSDs en endpoints (PCs y dispositivos móviles), HDDs y SSDs en servidores, unidades externas en la red local, medios ópticos (DVDs, discos Blu-ray, CDs), medios flash (USB sticks, tarjetas SD). La tecnología heredada puede incluir disquetes, unidades ZIP (un relicto de los 90s) y unidades de cinta.
    
- Todo el almacenamiento de datos que posee su proveedor de nube. [Amazon Web Services](https://aws.amazon.com/) (`AWS`), [Google Cloud Platform](https://cloud.google.com/) (`GCP`) y [Microsoft Azure](https://azure.microsoft.com/en-us/) son algunos de los proveedores de nube más populares, pero hay muchos más. A veces, las redes corporativas son "multi-nube", lo que significa que tienen más de un proveedor de nube. El proveedor de nube de una empresa proporcionará herramientas que se pueden usar para inventariar todos los datos almacenados por ese proveedor de nube en particular.
    
- Todos los datos almacenados dentro de varias aplicaciones de `Software-as-a-Service (SaaS)`. Estos datos también están "en la nube" pero pueden no estar todos dentro del alcance de una cuenta de proveedor de nube corporativa. A menudo, estos son servicios al consumidor o la versión "empresarial" de esos servicios. Piensa en servicios en línea como `Google Drive`, `Dropbox`, `Microsoft Teams`, `Apple iCloud`, `Adobe Creative Suite`, `Microsoft Office 365`, `Google Docs`, y la lista continúa.
    
- Todas las aplicaciones que una empresa necesita usar para llevar a cabo su operación y negocio habitual. Incluyendo aplicaciones que se despliegan localmente y aplicaciones que se despliegan a través de la nube o de otro modo son Software-as-a-Service.
    
- Todos los dispositivos de networking de la computadora en las instalaciones de una empresa. Estos incluyen pero no están limitados a `routers`, `firewalls`, `hubs`, `switches`, sistemas dedicados de `intrusion detection` y `prevention systems` (`IDS/IPS`), sistemas de `data loss prevention` (`DLP`), y así sucesivamente.
    

Todos estos activos son muy importantes. Un actor de amenazas o cualquier otro tipo de

 riesgo para cualquiera de estos activos puede hacer un daño significativo a la seguridad de la información de una empresa y a su capacidad para operar día a día. Una organización necesita tomarse su tiempo para evaluar todo y tener cuidado de no perderse un solo activo de datos, o no podrán protegerlo.

Las organizaciones frecuentemente agregan o eliminan computadoras, almacenamiento de datos, capacidad de servidores en la nube u otros activos de datos. Siempre que se agreguen o eliminen activos de datos, esto debe anotarse minuciosamente en el `data asset inventory`.

---

## Onwards

A continuación, discutiremos algunos estándares clave a los que las organizaciones pueden estar sujetas o elegir seguir para estandarizar su enfoque hacia la gestión de riesgos y vulnerabilidades.