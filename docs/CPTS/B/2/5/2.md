Esta vez, discutamos una vulnerabilidad que no tiene un CVE y no requiere un exploit directo. La sección anterior muestra que podemos obtener los hashes `NTLMv2` interactuando con el servidor MSSQL. Sin embargo, debemos mencionar nuevamente que este ataque es posible a través de una conexión directa al servidor MSSQL y aplicaciones web vulnerables. Sin embargo, nos enfocaremos solo en la variante más simple por el momento, es decir, la interacción directa.

---

## The Concept of the Attack

Nos centraremos en la función no documentada del servidor MSSQL llamada `xp_dirtree` para esta vulnerabilidad. Esta función se utiliza para ver el contenido de una carpeta específica (local o remota). Además, esta función proporciona algunos parámetros adicionales que se pueden especificar. Estos incluyen la profundidad, hasta dónde debe ir la función en la carpeta y la carpeta de destino real.

### The Concept of Attacks

![Concepto de Ataques](https://academy.hackthebox.com/storage/modules/116/attack_concept2.png)

Lo interesante es que la función `xp_dirtree` de MSSQL no es directamente una vulnerabilidad, sino que aprovecha el mecanismo de autenticación de SMB. Cuando intentamos acceder a una carpeta compartida en la red con un host de Windows, este host de Windows envía automáticamente un hash `NTLMv2` para la autenticación.

Este hash se puede usar de varias maneras contra el servidor MSSQL y otros hosts en la red corporativa. Esto incluye un ataque de SMB Relay donde "retransmitimos" el hash para iniciar sesión en otros sistemas donde la cuenta tiene privilegios de administrador local o `crackear` este hash en nuestro sistema local. Crackear con éxito nos permitiría ver y usar la contraseña en texto claro. Un ataque SMB Relay exitoso nos otorgaría derechos de administrador en otro host en la red, pero no necesariamente en el host de donde se originó el hash, porque Microsoft parcheó una falla anterior que permitía un SMB Relay de regreso al host de origen. Sin embargo, podríamos obtener privilegios de administrador local en otro host y luego robar credenciales que podrían reutilizarse para obtener acceso de administrador local al sistema original donde se originó el hash NTLMv2.

### Initiation of the Attack

| **Step** | **XP_DIRTREE**                                                                                                         | **Concept of Attacks - Category** |
| -------- | ---------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| `1.`     | La fuente aquí es la entrada del usuario, que especifica la función y la carpeta compartida en la red.                  | `Source`                          |
| `2.`     | El proceso debe asegurar que todos los contenidos de la carpeta especificada se muestren al usuario.                   | `Process`                         |
| `3.`     | La ejecución de comandos del sistema en el servidor MSSQL requiere privilegios elevados con los que el servicio ejecuta los comandos. | `Privileges`                      |
| `4.`     | El servicio SMB se usa como el destino al que se reenvía la información especificada.                                  | `Destination`                     |

Aquí es cuando el ciclo comienza de nuevo, pero esta vez para obtener el hash NTLMv2 del usuario del servicio MSSQL.

### Steal The Hash

| **Step** | **Stealing the Hash**                                                                                                         | **Concept of Attacks - Category** |
| -------- | ----------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| `5.`     | Aquí, el servicio SMB recibe la información sobre la orden especificada a través del proceso anterior del servicio MSSQL.     | `Source`                          |
| `6.`     | Luego, los datos se procesan y se consulta la carpeta especificada por los contenidos.                                        | `Process`                         |
| `7.`     | El hash de autenticación asociado se usa en consecuencia, ya que el usuario en ejecución de MSSQL consulta el servicio.       | `Privileges`                      |
| `8.`     | En este caso, el destino para la autenticación y consulta es el host que controlamos y la carpeta compartida en la red.       | `Destination`                     |

Finalmente, el hash es interceptado por herramientas como `Responder`, `WireShark` o `TCPDump` y se nos muestra, lo que podemos intentar usar para nuestros propósitos. Además de eso, hay muchas formas diferentes de ejecutar comandos en MSSQL. Por ejemplo, otro método interesante sería ejecutar código Python en una consulta SQL. Podemos encontrar más sobre esto en la [documentación](https://docs.microsoft.com/en-us/sql/machine-learning/tutorials/quickstart-python-create-script?view=sql-server-ver15) de Microsoft. Sin embargo, esto y otras posibilidades de lo que podemos hacer con MSSQL se discutirán en otro módulo.