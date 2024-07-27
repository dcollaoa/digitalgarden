Tanto Burp como ZAP tienen capacidades de extensión, de modo que la comunidad de usuarios de Burp puede desarrollar extensiones para Burp para que todos las utilicen. Estas extensiones pueden realizar acciones específicas en cualquier solicitud capturada, por ejemplo, o agregar nuevas funciones, como decodificar y embellecer el código. Burp permite la extensibilidad a través de su característica `Extender` y su [BApp Store](https://portswigger.net/bappstore), mientras que ZAP tiene su [ZAP Marketplace](https://www.zaproxy.org/addons/) para instalar nuevos plugins.

---

## BApp Store

Para encontrar todas las extensiones disponibles, podemos hacer clic en la pestaña `Extender` dentro de Burp y seleccionar la sub-pestaña `BApp Store`. Una vez que hagamos esto, veremos una serie de extensiones. Podemos ordenarlas por `Popularity` para saber cuáles son las más útiles según los usuarios:

![BApp Store](https://academy.hackthebox.com/storage/modules/110/burp_bapp_store.jpg)

Nota: Algunas extensiones son solo para usuarios Pro, mientras que la mayoría están disponibles para todos.

Vemos muchas extensiones útiles, tómate un tiempo para revisarlas y ver cuáles son las más útiles para ti, y luego intenta instalarlas y probarlas. Probemos instalando la extensión `Decoder Improved`:

![Burp Extension](https://academy.hackthebox.com/storage/modules/110/burp_extension.jpg)

Nota: Algunas extensiones tienen requisitos que normalmente no están instalados en Linux/macOS/Windows por defecto, como `Jython`, por lo que debes instalarlos antes de poder instalar la extensión.

Una vez que instalemos `Decoder Improved`, veremos su nueva pestaña añadida a Burp. Cada extensión tiene un uso diferente, por lo que podemos hacer clic en la documentación de cualquier extensión en `BApp Store` para leer más sobre ella o visitar su página de GitHub para obtener más información sobre su uso. Podemos usar esta extensión tal como usaríamos el Decoder de Burp, con el beneficio de tener muchos encoders adicionales incluidos. Por ejemplo, podemos ingresar texto que queremos que sea hashed con `MD5`, y seleccionar `Hash With>MD5`:

![Decoder Improved](https://academy.hackthebox.com/storage/modules/110/burp_extension_decoder_improved.jpg)

De manera similar, podemos realizar otros tipos de codificación y hashing. Hay muchas otras extensiones de Burp que se pueden utilizar para ampliar aún más la funcionalidad de Burp.

Algunas extensiones que vale la pena revisar incluyen, pero no se limitan a:

||||
|---|---|---|
|.NET beautifier|J2EEScan|Software Vulnerability Scanner|
|Software Version Reporter|Active Scan++|Additional Scanner Checks|
|AWS Security Checks|Backslash Powered Scanner|Wsdler|
|Java Deserialization Scanner|C02|Cloud Storage Tester|
|CMS Scanner|Error Message Checks|Detect Dynamic JS|
|Headers Analyzer|HTML5 Auditor|PHP Object Injection Check|
|JavaScript Security|Retire.JS|CSP Auditor|
|Random IP Address Header|Autorize|CSRF Scanner|
|JS Link Finder|||

---

## ZAP Marketplace

ZAP también tiene su propia característica de extensibilidad con el `Marketplace` que nos permite instalar varios tipos de complementos desarrollados por la comunidad. Para acceder al marketplace de ZAP, podemos hacer clic en el botón `Manage Add-ons` y luego seleccionar la pestaña `Marketplace`:

![Marketplace Button](https://academy.hackthebox.com/storage/modules/110/zap_marketplace_button.jpg)

En esta pestaña, podemos ver los diferentes complementos disponibles para ZAP. Algunos complementos pueden estar en su versión `Release`, lo que significa que deberían ser estables para su uso, mientras que otros están en sus versiones `Beta/Alpha`, lo que significa que pueden experimentar algunos problemas en su uso. Probemos instalando los complementos `FuzzDB Files` y `FuzzDB Offensive`, que añaden nuevas listas de palabras para ser utilizadas en el fuzzer de ZAP:

![Install FuzzDB](https://academy.hackthebox.com/storage/modules/110/zap_fuzzdb_install.jpg)

Ahora, tendremos la opción de elegir entre las diversas listas de palabras y payloads proporcionados por FuzzDB al realizar un ataque. Por ejemplo, supongamos que vamos a realizar un ataque de fuzzing de Command Injection en uno de los ejercicios que usamos anteriormente en este módulo. En ese caso, veremos que tenemos más opciones en las listas de palabras `File Fuzzers`, incluyendo una lista de palabras de OS Command Injection bajo (`fuzzdb>attack>os-cmd-execution`), que sería perfecta para este ataque:

![FuzzDB CMD Exec](https://academy.hackthebox.com/storage/modules/110/zap_fuzzdb_cmd_exec.jpg)

Ahora, si ejecutamos el fuzzer en nuestro ejercicio usando la lista de palabras anterior, veremos que pudo explotarlo de varias maneras, lo cual sería muy útil si estuviéramos lidiando con una aplicación web protegida por un WAF:

![FuzzDB CMD Exec](https://academy.hackthebox.com/storage/modules/110/zap_fuzzer_cmd_inj.jpg)

Intenta repetir lo anterior con el primer ejercicio en este módulo para ver cómo los complementos pueden ayudar a facilitar tu penetration test.

---

## Closing Thoughts

A lo largo de este módulo, hemos demostrado el poder de ambos proxies, Burp Suite y ZAP, y hemos analizado las diferencias y similitudes entre las versiones gratuitas y pro de Burp y la versión gratuita y de código abierto del proxy ZAP. Estas herramientas son esenciales para los penetration testers enfocados en evaluaciones de seguridad de aplicaciones web, pero tienen muchas aplicaciones para todos los practicantes de seguridad ofensiva, así como para los practicantes de blue team y desarrolladores. Después de trabajar en cada uno de los ejemplos y ejercicios en este módulo, intenta algunos boxes enfocados en ataques web en la plataforma principal de Hack The Box y otros módulos relacionados con la seguridad de aplicaciones web dentro de HTB Academy para fortalecer tus habilidades en torno a ambas herramientas. Son imprescindibles en tu caja de herramientas junto con Nmap, Hashcat, Wireshark, tcpdump, sqlmap, Ffuf, Gobuster, etc.