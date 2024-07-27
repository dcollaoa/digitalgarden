Nuestro cliente, Inlanefreight, ha contratado nuestra compañía, Acme Security, Ltd., para realizar un **External Penetration Test** de alcance completo con el fin de evaluar la seguridad de su perímetro. El cliente nos ha pedido identificar la mayor cantidad de vulnerabilidades posible; por lo tanto, las pruebas evasivas no son necesarias. Quieren ver qué tipo de acceso puede lograr un usuario anónimo en Internet. Según las **Rules of Engagement (RoE)**, si podemos romper la DMZ y obtener un punto de apoyo en la red interna, quieren que veamos hasta dónde podemos llegar con ese acceso, incluyendo el compromiso del **Active Directory domain**. El cliente no ha proporcionado credenciales de usuario para aplicaciones web, VPN o Active Directory. Los siguientes dominios y rangos de red están dentro del alcance de la prueba:

|**External Testing**|**Internal Testing**|
|---|---|
|10.129.x.x ("external" facing target host)|172.16.8.0/23|
|*.inlanefreight.local (all subdomains)|172.16.9.0/23|
||INLANEFREIGHT.LOCAL (Active Directory domain)|

El cliente ha proporcionado el dominio principal y las redes internas, pero no ha dado detalles sobre los subdominios exactos dentro de este alcance ni los hosts "live" que encontraremos en la red. Quieren que realicemos un descubrimiento para ver qué tipo de visibilidad puede obtener un atacante contra su red externa (e interna si se logra un punto de apoyo).

Las técnicas de prueba automatizadas como la enumeración y el escaneo de vulnerabilidades están permitidas, pero debemos trabajar con cuidado para no causar interrupciones en el servicio. Lo siguiente está fuera del alcance de esta evaluación:

- Phishing/Ingeniería social contra empleados o clientes de Inlanefreight
- Ataques físicos contra instalaciones de Inlanefreight
- Acciones destructivas o pruebas de **Denial of Service (DoS)**
- Modificaciones al entorno sin el consentimiento por escrito del personal de TI autorizado de Inlanefreight

---

## Project Kickoff

En este punto, tenemos un **Scope of Work (SoW)** firmado tanto por la gerencia de nuestra compañía como por un miembro autorizado del departamento de TI de Inlanefreight. Este documento **SoW** enumera los detalles de la prueba, nuestra metodología, el cronograma y las reuniones y entregables acordados. El cliente también firmó un documento separado de **Rules of Engagement (RoE)**, comúnmente conocido como documento de autorización para pruebas. Este documento es crucial tenerlo en mano antes de comenzar las pruebas y enumera el alcance de todos los tipos de evaluación (URLs, direcciones IP individuales, rangos de red **CIDR**, y credenciales, si aplica). Este documento también enumera al personal clave de la compañía de pruebas y de Inlanefreight (un mínimo de dos contactos para cada lado, incluyendo su número de celular y dirección de correo electrónico). El documento también enumera detalles como la fecha de inicio y finalización de la prueba y la ventana de prueba permitida.

Se nos ha dado una semana para las pruebas y dos días adicionales para escribir nuestro informe preliminar (que debemos ir trabajando a medida que avanzamos). El cliente nos ha autorizado a probar 24/7, pero nos ha pedido que ejecutemos cualquier escaneo de vulnerabilidades pesado fuera del horario laboral regular (después de las 18:00, hora de Londres). Hemos revisado todos los documentos necesarios y tenemos las firmas requeridas de ambas partes, y el alcance está completamente lleno, por lo que estamos listos para comenzar desde una perspectiva administrativa.

---

## Start of Testing

Es lunes por la mañana y estamos listos para comenzar las pruebas. Nuestra máquina virtual de prueba está configurada y lista para funcionar, y hemos configurado una estructura de notas y directorio esqueleto para tomar notas usando nuestra herramienta de toma de notas favorita. Mientras nuestros escaneos de descubrimiento iniciales se ejecutan, como siempre, llenaremos la mayor cantidad posible de la plantilla del informe. Esta es una pequeña eficiencia que podemos ganar mientras esperamos que los escaneos se completen para optimizar el tiempo que tenemos para las pruebas. Hemos redactado el siguiente correo electrónico para señalar el inicio de las pruebas y hemos copiado a todo el personal necesario.

![text](https://academy.hackthebox.com/storage/modules/163/start_testing.png)

Hacemos clic en enviar en el correo electrónico y comenzamos nuestra recopilación de información externa.