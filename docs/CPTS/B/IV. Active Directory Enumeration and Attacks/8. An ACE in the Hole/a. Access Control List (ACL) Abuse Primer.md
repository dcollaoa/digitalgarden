Por razones de seguridad, no todos los usuarios y computadoras en un entorno de AD pueden acceder a todos los objetos y archivos. Este tipo de permisos se controlan a través de las Access Control Lists (ACLs). Representando una seria amenaza para la postura de seguridad del dominio, una ligera mala configuración en una ACL puede filtrar permisos a otros objetos que no los necesitan.

---

## Access Control List (ACL) Overview

En su forma más simple, las ACLs son listas que definen a) quién tiene acceso a qué recurso y b) el nivel de acceso que se les proporciona. Las configuraciones en sí en una ACL se llaman `Access Control Entries` (`ACEs`). Cada ACE se asigna a un usuario, grupo o proceso (también conocido como security principals) y define los derechos otorgados a ese principal. Cada objeto tiene una ACL, pero puede tener múltiples ACEs porque múltiples security principals pueden acceder a objetos en AD. Las ACLs también se pueden usar para auditar el acceso dentro de AD.

Hay dos tipos de ACLs:

1. `Discretionary Access Control List` (`DACL`) - define qué security principals tienen concedido o denegado el acceso a un objeto. Las DACLs están compuestas de ACEs que permiten o deniegan acceso. Cuando alguien intenta acceder a un objeto, el sistema verificará la DACL para el nivel de acceso permitido. Si no existe una DACL para un objeto, todos los que intenten acceder al objeto tendrán todos los derechos. Si existe una DACL, pero no tiene ninguna entrada ACE que especifique configuraciones de seguridad específicas, el sistema denegará el acceso a todos los usuarios, grupos o procesos que intenten acceder.
    
2. `System Access Control Lists` (`SACL`) - permiten a los administradores registrar intentos de acceso a objetos seguros.
    
Vemos la ACL para la cuenta de usuario `forend` en la imagen a continuación. Cada elemento bajo `Permission entries` conforma la `DACL` para la cuenta de usuario, mientras que las entradas individuales (como `Full Control` o `Change Password`) son entradas ACE que muestran los derechos otorgados sobre este objeto de usuario a varios usuarios y grupos.

### Viewing forend's ACL

![image](https://academy.hackthebox.com/storage/modules/143/DACL_example.png)

Los SACLs se pueden ver dentro de la pestaña `Auditing`.

### Viewing the SACLs through the Auditing Tab

![image](https://academy.hackthebox.com/storage/modules/143/SACL_example.png)

---

## Access Control Entries (ACEs)

Como se mencionó anteriormente, las Access Control Lists (ACLs) contienen entradas ACE que nombran a un usuario o grupo y el nivel de acceso que tienen sobre un objeto seguro. Hay `tres` tipos principales de ACEs que se pueden aplicar a todos los objetos seguros en AD:

| **ACE**              | **Descripción**                                                                                                                                                                           |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Access denied ACE`  | Usado dentro de una DACL para mostrar que a un usuario o grupo se le niega explícitamente el acceso a un objeto                                                                           |
| `Access allowed ACE` | Usado dentro de una DACL para mostrar que a un usuario o grupo se le concede explícitamente el acceso a un objeto                                                                         |
| `System audit ACE`   | Usado dentro de una SACL para generar registros de auditoría cuando un usuario o grupo intenta acceder a un objeto. Registra si el acceso fue concedido o no y qué tipo de acceso ocurrió |

Cada ACE se compone de los siguientes `cuatro` componentes:

1. El identificador de seguridad (SID) del usuario/grupo que tiene acceso al objeto (o el nombre del principal gráficamente)
2. Una flag que denota el tipo de ACE (access denied, allowed, o system audit ACE)
3. Un conjunto de flags que especifican si los contenedores/objetos secundarios pueden heredar la entrada ACE dada del objeto primario o padre
4. Una [access mask](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN) que es un valor de 32 bits que define los derechos otorgados a un objeto

Podemos ver esto gráficamente en `Active Directory Users and Computers` (`ADUC`). En la imagen de ejemplo a continuación, podemos ver lo siguiente para la entrada ACE para el usuario `forend`:

### Viewing Permissions through Active Directory Users & Computers

![image](https://academy.hackthebox.com/storage/modules/143/ACE_example.png)

1. El security principal es Angela Dunn (adunn@inlanefreight.local)
2. El tipo de ACE es `Allow`
3. La herencia se aplica a "This object and all descendant objects," lo que significa que cualquier objeto secundario del objeto `forend` tendría los mismos permisos otorgados
4. Los derechos otorgados al objeto, nuevamente mostrados gráficamente en este ejemplo

Cuando se revisan las access control lists para determinar permisos, se revisan de arriba a abajo hasta que se encuentra un acceso denegado en la lista.

---

## Why are ACEs Important?

Los atacantes utilizan entradas ACE para obtener acceso adicional o establecer persistencia. Estas pueden ser muy útiles para nosotros como penetration testers ya que muchas organizaciones no son conscientes de las ACEs aplicadas a cada objeto o del impacto que pueden tener si se aplican incorrectamente. No pueden ser detectadas por herramientas de escaneo de vulnerabilidades, y a menudo pasan desapercibidas durante muchos años, especialmente en entornos grandes y complejos. Durante una evaluación donde el cliente ha cuidado todos los defectos/misconfiguraciones de AD "low hanging fruit", el abuso de ACL puede ser una excelente manera de movernos lateralmente/verticalmente e incluso lograr un compromiso completo del dominio. Algunos ejemplos de permisos de seguridad de objetos en Active Directory son los siguientes. Estos pueden ser enumerados (y visualizados) usando una herramienta como BloodHound, y todos son abusables con PowerView, entre otras herramientas:

- `ForceChangePassword` abusado con `Set-DomainUserPassword`
- `Add Members` abusado con `Add-DomainGroupMember`
- `GenericAll` abusado con `Set-DomainUserPassword` o `Add-DomainGroupMember`
- `GenericWrite` abusado con `Set-DomainObject`
- `WriteOwner` abusado con `Set-DomainObjectOwner`
- `WriteDACL` abusado con `Add-DomainObjectACL`
- `AllExtendedRights` abusado con `Set-DomainUserPassword` o `Add-DomainGroupMember`
- `Addself` abusado con `Add-DomainGroupMember`

En este módulo, cubriremos la enumeración y el aprovechamiento de cuatro ACEs específicos para resaltar el poder de los ataques de ACL:

- [ForceChangePassword](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#forcechangepassword) - nos da el derecho de restablecer la contraseña de un usuario sin conocer primero su contraseña (debe usarse con precaución y, por lo general, es mejor consultar a nuestro cliente antes de restablecer contraseñas).
- [GenericWrite](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericwrite) - nos da el derecho de escribir en cualquier atributo no protegido en un objeto. Si tenemos este acceso sobre un usuario, podríamos asignarle un SPN y realizar un ataque de Kerberoasting (que depende de que la cuenta objetivo tenga una contraseña débil establecida). Sobre un grupo significa que podríamos agregarnos a nosotros mismos o a otro security principal a un grupo dado. Finalmente, si tenemos este acceso sobre un objeto de computadora, podríamos realizar un ataque de resource-based constrained delegation, que está fuera del alcance de este módulo.
- `AddSelf` - muestra los grupos de seguridad a los que un usuario puede agregarse.
- [GenericAll](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericall) - esto nos otorga control total sobre un objeto objetivo. Nuevamente, dependiendo de si esto se otorga sobre un usuario o grupo, podríamos modificar la membresía del grupo, forzar el cambio de una contraseña o realizar un ataque de Kerberoasting dirigido. Si tenemos este acceso sobre un objeto de computadora y la [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) está en uso en el entorno, podemos leer la contraseña LAPS y obtener acceso de administrador local a la máquina, lo que puede ayudarnos en el movimiento lateral o en la escalada de privilegios en el dominio si podemos obtener controles privilegiados o algún tipo de acceso privilegiado.

Este gráfico, adaptado de un gráfico creado por [Charlie Bromberg (Shutdown)](https://twitter.com/_nwodtuhs), muestra un excelente desglose de los posibles ataques de ACE y las herramientas para realizar estos ataques desde Windows y Linux (si es aplicable). En las siguientes secciones, cubriremos principalmente la enumeración y realización de estos ataques desde un host de ataque Windows con menciones de cómo estos ataques podrían realizarse desde Linux. Un módulo posterior específicamente sobre ataques de ACL profundizará mucho más en cada uno de los ataques listados en este gráfico y cómo realizarlos desde Windows y Linux.

![image](https://academy.hackthebox.com/storage/modules/143/ACL_attacks_graphic.png)

Nos encontraremos con muchas otras ACEs (privilegios) interesantes en Active Directory de vez en cuando. La metodología para enumerar posibles ataques de ACL usando herramientas como BloodHound y PowerView e incluso herramientas de administración de AD integr

adas debería ser lo suficientemente adaptable para ayudarnos siempre que encontremos nuevos privilegios en el campo que aún no conozcamos. Por ejemplo, podemos importar datos en BloodHound y ver que un usuario sobre el que tenemos control (o que podemos tomar) tiene los derechos para leer la contraseña de una Group Managed Service Account (gMSA) a través del borde [ReadGMSAPassword](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#readgmsapassword). En este caso, hay herramientas como [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader) que podríamos usar, junto con otros métodos, para obtener la contraseña de la cuenta de servicio en cuestión. Otras veces podemos encontrar derechos extendidos como [Unexpire-Password](https://learn.microsoft.com/en-us/windows/win32/adschema/r-unexpire-password) o [Reanimate-Tombstones](https://learn.microsoft.com/en-us/windows/win32/adschema/r-reanimate-tombstones) usando PowerView y tener que investigar un poco para descubrir cómo explotarlos en nuestro beneficio. Vale la pena familiarizarse con todos los [BloodHound edges](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html) y tantos [Extended Rights](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights) de Active Directory como sea posible, ya que nunca se sabe cuándo podemos encontrarnos con uno menos común durante una evaluación.

---

## ACL Attacks in the Wild

Podemos usar ataques de ACL para:

- Movimiento lateral
- Escalada de privilegios
- Persistencia

Algunos escenarios de ataque comunes pueden incluir:

|Ataque|Descripción|
|---|---|
|`Abusing forgot password permissions`|Help Desk y otros usuarios de TI a menudo tienen permisos para restablecer contraseñas y realizar otras tareas privilegiadas. Si podemos tomar el control de una cuenta con estos privilegios (o una cuenta en un grupo que confiere estos privilegios a sus usuarios), podríamos realizar un restablecimiento de contraseña para una cuenta más privilegiada en el dominio.|
|`Abusing group membership management`|También es común ver a Help Desk y otro personal que tiene el derecho de agregar/quitar usuarios de un grupo determinado. Siempre vale la pena enumerar esto más a fondo, ya que a veces podemos agregar una cuenta que controlamos a un grupo de AD privilegiado o a un grupo que nos otorgue algún tipo de privilegio interesante.|
|`Excessive user rights`|También vemos comúnmente objetos de usuario, computadora y grupo con derechos excesivos que el cliente probablemente no conozca. Esto podría ocurrir después de algún tipo de instalación de software (Exchange, por ejemplo, agrega muchos cambios de ACL en el entorno en el momento de la instalación) o algún tipo de configuración heredada o accidental que otorgue a un usuario derechos no intencionados. A veces podemos tomar el control de una cuenta a la que se le dieron ciertos derechos por conveniencia o para resolver un problema persistente más rápidamente.|

Hay muchos otros posibles escenarios de ataque en el mundo de las ACLs de Active Directory, pero estos tres son los más comunes. Cubriremos la enumeración de estos derechos de varias maneras, la realización de los ataques y la limpieza después de nosotros mismos.

**Nota:** Algunos ataques de ACL pueden considerarse "destructivos", como cambiar la contraseña de un usuario o realizar otras modificaciones dentro del dominio de AD de un cliente. En caso de duda, siempre es mejor comunicar un ataque dado a nuestro cliente antes de realizarlo para tener documentación escrita de su aprobación en caso de que surja un problema. Siempre debemos documentar cuidadosamente nuestros ataques de principio a fin y revertir cualquier cambio. Estos datos deben incluirse en nuestro informe, pero también debemos resaltar cualquier cambio que realicemos claramente para que el cliente pueda volver y verificar que nuestros cambios se hayan revertido correctamente.