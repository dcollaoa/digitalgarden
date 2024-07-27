Tanto las pruebas de penetración como las evaluaciones de vulnerabilidades deben cumplir con estándares específicos para ser acreditadas y aceptadas por gobiernos y autoridades legales. Dichos estándares ayudan a garantizar que la evaluación se realice de manera exhaustiva y de acuerdo con un método generalmente aceptado para aumentar la eficiencia de estas evaluaciones y reducir la probabilidad de un ataque a la organización.

---

## Compliance Standards

Cada organismo regulador de cumplimiento tiene sus propios estándares de seguridad de la información a los que las organizaciones deben adherirse para mantener su acreditación. Los grandes actores del cumplimiento en seguridad de la información son `PCI`, `HIPAA`, `FISMA` e `ISO 27001`.

Estas acreditaciones son necesarias porque certifican que una organización ha sido evaluada por un proveedor externo. Las organizaciones también dependen de estas acreditaciones para sus operaciones comerciales, ya que algunas empresas no harán negocios sin acreditaciones específicas de ciertas organizaciones.

### Payment Card Industry Data Security Standard (PCI DSS)

El [Payment Card Industry Data Security Standard (PCI DSS)](https://www.pcisecuritystandards.org/pci_security/) es un estándar conocido en seguridad de la información que implementa requisitos para las organizaciones que manejan tarjetas de crédito. Aunque no es una regulación gubernamental, las organizaciones que almacenan, procesan o transmiten datos de titulares de tarjetas deben implementar las directrices de PCI DSS. Esto incluiría bancos o tiendas en línea que manejan sus propias soluciones de pago (por ejemplo, Amazon).

Los requisitos de PCI DSS incluyen escaneos internos y externos de activos. Por ejemplo, cualquier dato de tarjeta de crédito que se esté procesando o transmitiendo debe hacerse en un Cardholder Data Environment (CDE). El entorno CDE debe estar adecuadamente segmentado de los activos normales. Los entornos CDE están segmentados del entorno regular de una organización para proteger cualquier dato de titular de tarjeta de ser comprometido durante un ataque y limitar el acceso interno a los datos.

![PCIDSS goals](https://academy.hackthebox.com/storage/modules/108/graphics/PCI-DSS-Goals.png) [Source](https://adktechs.com/wp-content/uploads/2019/06/PCI-DSS-Goals.png)

### Health Insurance Portability and Accountability Act (HIPAA)

`HIPAA` es la [Health Insurance Portability and Accountability Act](https://www.hhs.gov/programs/hipaa/index.html), que se utiliza para proteger los datos de los pacientes. HIPAA no necesariamente requiere escaneos o evaluaciones de vulnerabilidades; sin embargo, se requiere una evaluación de riesgos e identificación de vulnerabilidades para mantener la acreditación HIPAA.

### Federal Information Security Management Act (FISMA)

El [Federal Information Security Management Act (FISMA)](https://www.cisa.gov/federal-information-security-modernization-act) es un conjunto de estándares y directrices utilizados para proteger las operaciones e información gubernamentales. La ley requiere que una organización proporcione documentación y prueba de un programa de gestión de vulnerabilidades para mantener la disponibilidad, confidencialidad e integridad adecuadas de los sistemas de tecnología de la información.

### ISO 27001

`ISO 27001` es un estándar utilizado a nivel mundial para gestionar la seguridad de la información. [ISO 27001](https://www.iso.org/isoiec-27001-information-security.html) requiere que las organizaciones realicen escaneos externos e internos trimestrales.

Aunque el cumplimiento es esencial, no debería ser el impulsor principal de un programa de gestión de vulnerabilidades. La gestión de vulnerabilidades debe considerar la singularidad de un entorno y el apetito de riesgo asociado a una organización.

La `International Organization for Standardization` (`ISO`) mantiene estándares técnicos para prácticamente cualquier cosa que puedas imaginar. El estándar [ISO 27001](https://www.iso.org/isoiec-27001-information-security.html) trata sobre la seguridad de la información. El cumplimiento de ISO 27001 depende de mantener un Sistema de Gestión de Seguridad de la Información efectivo. Para asegurar el cumplimiento, las organizaciones deben realizar pruebas de penetración de manera cuidadosamente diseñada.

---

## Penetration Testing Standards

Las pruebas de penetración no deben realizarse sin ninguna `rules` o `guidelines`. Siempre debe haber un alcance específicamente definido para un pentest, y el propietario de una red debe tener un `signed legal contract` con los pentesters que describa lo que se les permite hacer y lo que no se les permite hacer. El pentesting también debe realizarse de tal manera que se minimice el daño a las computadoras y redes de una empresa. Los pentesters deben evitar hacer cambios siempre que sea posible (como cambiar una contraseña de cuenta) y limitar la cantidad de datos removidos de la red de un cliente. Por ejemplo, en lugar de eliminar documentos sensibles de un recurso compartido de archivos, una captura de pantalla de los nombres de las carpetas debería ser suficiente para probar el riesgo.

Además del alcance y las legalidades, también existen varios estándares de pentesting, dependiendo del tipo de sistema informático que se esté evaluando. Aquí hay algunos de los estándares más comunes que puedes usar como pentester.

### PTES

El [Penetration Testing Execution Standard](http://www.pentest-standard.org/index.php/Main_Page) (`PTES`) se puede aplicar a todos los tipos de pruebas de penetración. Describe las fases de una prueba de penetración y cómo deben llevarse a cabo. Estas son las secciones en el PTES:

- Pre-engagement Interactions
- Intelligence Gathering
- Threat Modeling
- Vulnerability Analysis
- Exploitation
- Post Exploitation
- Reporting

### OSSTMM

`OSSTMM` es el `Open Source Security Testing Methodology Manual`, otro conjunto de directrices que los pentesters pueden usar para asegurarse de que están haciendo bien su trabajo. Puede usarse junto con otros estándares de pentesting.

[OSSTMM](https://www.isecom.org/OSSTMM.3.pdf) está dividido en cinco canales diferentes para cinco áreas diferentes de pentesting:

1. Human Security (los seres humanos están sujetos a exploits de ingeniería social)
2. Physical Security
3. Wireless Communications (incluyendo pero no limitado a tecnologías como WiFi y Bluetooth)
4. Telecommunications
5. Data Networks

### NIST

El `NIST` (`National Institute of Standards and Technology`) es bien conocido por su [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework), un sistema para diseñar políticas y procedimientos de respuesta a incidentes. NIST también tiene un Penetration Testing Framework. Las fases del marco de NIST incluyen:

- Planning
- Discovery
- Attack
- Reporting

### OWASP

`OWASP` significa [Open Web Application Security Project](https://owasp.org/). Por lo general, son la organización de referencia para definir estándares de pruebas y clasificar riesgos para aplicaciones web.

OWASP mantiene algunos estándares diferentes y guías útiles para la evaluación de diversas tecnologías:

- [Web Security Testing Guide (WSTG)](https://owasp.org/www-project-web-security-testing-guide/)
- [Mobile Security Testing Guide (MSTG)](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Firmware Security Testing Methodology](https://github.com/scriptingxss/owasp-fstm)