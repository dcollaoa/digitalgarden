Dado que las aplicaciones web se están volviendo muy comunes y se utilizan en la mayoría de los negocios, la importancia de protegerlas contra ataques maliciosos también se vuelve más crítica. A medida que las aplicaciones web modernas se vuelven más complejas y avanzadas, también lo hacen los tipos de ataques utilizados contra ellas. Esto lleva a una vasta superficie de ataque para la mayoría de las empresas hoy en día, razón por la cual los ataques web son los tipos más comunes de ataques contra las empresas. Proteger las aplicaciones web se está convirtiendo en una de las principales prioridades para cualquier departamento de IT.

Atacar aplicaciones web de cara al exterior puede resultar en el compromiso de la red interna de las empresas, lo que eventualmente puede llevar al robo de activos o a la interrupción de servicios. Potencialmente, puede causar un desastre financiero para la empresa. Incluso si una empresa no tiene aplicaciones web de cara al exterior, es probable que utilice aplicaciones web internas o endpoints de API de cara al exterior, ambos vulnerables a los mismos tipos de ataques y que pueden ser aprovechados para lograr los mismos objetivos.

Aunque otros módulos de HTB Academy cubrieron varios temas sobre aplicaciones web y diversos tipos de técnicas de explotación web, en este módulo, cubriremos tres otros ataques web que se pueden encontrar en cualquier aplicación web, los cuales pueden llevar a comprometerla. Discutiremos cómo detectar, explotar y prevenir cada uno de estos tres ataques.

---

## Web Attacks

### HTTP Verb Tampering

El primer ataque web discutido en este módulo es [HTTP Verb Tampering](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering). Un ataque de HTTP Verb Tampering explota servidores web que aceptan muchos verbos y métodos HTTP. Esto se puede explotar enviando solicitudes maliciosas utilizando métodos inesperados, lo que puede llevar a eludir el mecanismo de autorización de la aplicación web o incluso eludir sus controles de seguridad contra otros ataques web. Los ataques de HTTP Verb Tampering son uno de muchos otros ataques HTTP que se pueden utilizar para explotar configuraciones de servidores web enviando solicitudes HTTP maliciosas.

### Insecure Direct Object References (IDOR)

El segundo ataque discutido en este módulo es [Insecure Direct Object References (IDOR)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References). IDOR es una de las vulnerabilidades web más comunes y puede llevar al acceso de datos que no deberían ser accesibles para los atacantes. Lo que hace que este ataque sea muy común es, esencialmente, la falta de un sistema de control de acceso sólido en el back-end. A medida que las aplicaciones web almacenan archivos e información de los usuarios, pueden usar números secuenciales o IDs de usuarios para identificar cada ítem. Si la aplicación web carece de un mecanismo robusto de control de acceso y expone referencias directas a archivos y recursos, podemos acceder a los archivos e información de otros usuarios simplemente adivinando o calculando sus IDs de archivo.

### XML External Entity (XXE) Injection

El tercer y último ataque web que discutiremos es [XML External Entity (XXE) Injection](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing). Muchas aplicaciones web procesan datos XML como parte de su funcionalidad. Si una aplicación web utiliza bibliotecas XML desactualizadas para analizar y procesar datos XML de entrada del usuario del front-end, puede ser posible enviar datos XML maliciosos para divulgar archivos locales almacenados en el servidor back-end. Estos archivos pueden ser archivos de configuración que contengan información sensible como contraseñas o incluso el código fuente de la aplicación web, lo que nos permitiría realizar una prueba de penetración Whitebox en la aplicación web para identificar más vulnerabilidades. Los ataques XXE incluso pueden ser aprovechados para robar las credenciales del servidor de hosting, lo que comprometería todo el servidor y permitiría la ejecución remota de código.

Comencemos discutiendo el primero de estos ataques en la siguiente sección.