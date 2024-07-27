Nosotros somos Penetration Testers trabajando para `CAT-5 Security`. Después de varios compromisos exitosos observando con el equipo, los miembros más experimentados quieren ver qué tan bien podemos comenzar una evaluación por nuestra cuenta. El líder del equipo nos envió el siguiente correo detallando lo que necesitamos lograr.

### Tasking Email

![image](https://academy.hackthebox.com/storage/modules/143/scenario-email.png)

Este módulo nos permitirá practicar nuestras habilidades (tanto las previas como las recién adquiridas) con estas tareas. La evaluación final de este módulo consiste en la ejecución de `dos` tests de penetración internos contra la compañía Inlanefreight. Durante estas evaluaciones, trabajaremos en un test de penetración interna simulando comenzar desde una posición de brecha externa y un segundo comenzando con una caja de ataque dentro de la red interna como los clientes suelen solicitar. Completar las evaluaciones de habilidades significa la finalización exitosa de las tareas mencionadas en el documento de alcance y el correo de asignación anterior. Al hacerlo, demostraremos un firme entendimiento de muchos conceptos de ataque y enumeración de AD automáticos y manuales, conocimiento y experiencia con una amplia variedad de herramientas, y la capacidad de interpretar los datos recopilados de un entorno de AD para tomar decisiones críticas para avanzar en la evaluación. El contenido de este módulo está diseñado para cubrir conceptos esenciales de enumeración necesarios para que cualquiera tenga éxito en la realización de tests de penetración interna en entornos de Active Directory. También cubriremos muchas de las técnicas de ataque más comunes en gran profundidad mientras trabajamos en algunos conceptos más avanzados como una introducción al material centrado en AD que se cubrirá en módulos más avanzados.

A continuación, encontrarás un documento de alcance completo para el compromiso que contiene toda la información pertinente proporcionada por el cliente.

---

## Assessment Scope

Los siguientes `IPs`, `hosts` y `domains` definidos a continuación conforman el alcance de la evaluación.

### In Scope For Assessment

|**Range/Domain**|**Description**|
|---|---|
|`INLANEFREIGHT.LOCAL`|Dominio del cliente que incluye AD y servicios web.|
|`LOGISTICS.INLANEFREIGHT.LOCAL`|Subdominio del cliente|
|`FREIGHTLOGISTICS.LOCAL`|Compañía subsidiaria propiedad de Inlanefreight. Confianza de bosque externa con INLANEFREIGHT.LOCAL|
|`172.16.5.0/23`|Subred interna dentro del alcance.|
|||

### Out Of Scope

- `Cualquier otro subdominio de INLANEFREIGHT.LOCAL`
- `Cualquier subdominio de FREIGHTLOGISTICS.LOCAL`
- `Cualquier ataque de phishing o ingeniería social`
- `Cualquier otro IPS/dominios/subdominios no mencionados explícitamente`
- `Cualquier tipo de ataque contra el sitio web real de inlanefreight.com fuera de la enumeración pasiva mostrada en este módulo`

---

## Methods Used

Los siguientes métodos están autorizados para evaluar Inlanefreight y sus sistemas:

### External Information Gathering (Passive Checks)

La recopilación de información externa está autorizada para demostrar los riesgos asociados con la información que se puede recopilar sobre la compañía desde internet. Para simular un ataque real, CAT-5 y sus evaluadores llevarán a cabo la recopilación de información externa desde una perspectiva anónima en internet sin información previa proporcionada sobre Inlanefreight fuera de lo que se proporciona en este documento.

CAT-5 realizará la enumeración pasiva para descubrir información que pueda ayudar con las pruebas internas. Las pruebas emplearán varios grados de recopilación de información de recursos de código abierto para identificar datos públicamente accesibles que puedan representar un riesgo para Inlanefreight y ayudar con el test de penetración interno. No se realizará ninguna enumeración activa, escaneos de puertos o ataques contra direcciones IP de "mundo real" orientadas a internet o el sitio web ubicado en `https://www.inlanefreight.com`.

### Internal Testing

La parte de evaluación interna está diseñada para demostrar los riesgos asociados con las vulnerabilidades en hosts y servicios internos (`Active Directory específicamente`) al intentar emular vectores de ataque desde dentro del área de operaciones de Inlanefreight. El resultado permitirá a Inlanefreight evaluar los riesgos de las vulnerabilidades internas y el impacto potencial de una vulnerabilidad explotada con éxito.

Para simular un ataque real, CAT-5 llevará a cabo la evaluación desde una perspectiva de insider no confiable sin información previa fuera de lo que se proporciona en esta documentación y descubierto a partir de pruebas externas. Las pruebas comenzarán desde una posición anónima en la red interna con el objetivo de obtener credenciales de usuario del dominio, enumerar el dominio interno, obtener una posición de apoyo y moverse lateral y verticalmente para lograr comprometer todos los dominios internos en el alcance. Los sistemas informáticos y las operaciones de red no serán interrumpidos intencionalmente durante la prueba.

### Password Testing

Los archivos de contraseñas capturados de dispositivos de Inlanefreight, o proporcionados por la organización, pueden cargarse en estaciones de trabajo fuera de línea para su descifrado y utilizarse para obtener más acceso y cumplir con los objetivos de la evaluación. En ningún momento se revelará un archivo de contraseñas capturado o las contraseñas descifradas a personas que no participen oficialmente en la evaluación. Todos los datos se almacenarán de forma segura en sistemas propiedad y aprobados por CAT-5 y se retendrán durante un período de tiempo definido en el contrato oficial entre CAT-5 e Inlanefreight.

---

Proporcionamos la documentación de alcance anterior para que nos acostumbremos a ver este estilo de documentación. A medida que avancemos en nuestras carreras de Infosec, especialmente en el lado ofensivo, será común recibir documentos de alcance y documentos de Reglas de Compromiso (RoE) que describen este tipo de información.

---

## The Stage Is Set

Ahora que tenemos nuestro alcance claramente definido para este módulo, podemos sumergirnos en la exploración de la enumeración de Active Directory y los vectores de ataque. Ahora, vamos a realizar la enumeración externa pasiva contra Inlanefreight.