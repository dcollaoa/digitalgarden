Muchas personas crean sus contraseñas basándose en la `simplicity instead of security`. Para eliminar esta debilidad humana que a menudo compromete las medidas de seguridad, se pueden crear políticas de contraseñas en todos los sistemas que determinen cómo debe ser una contraseña. Esto significa que el sistema reconoce si la contraseña contiene letras mayúsculas, caracteres especiales y números. Además, la mayoría de las políticas de contraseñas requieren una longitud mínima de ocho caracteres en una contraseña, incluyendo al menos una de las especificaciones anteriores.

En las secciones anteriores, adivinamos contraseñas muy simples, pero se vuelve mucho más difícil adaptar esto a sistemas que aplican políticas de contraseñas que obligan a la creación de contraseñas más complejas.

Desafortunadamente, la tendencia de los usuarios a crear contraseñas débiles también ocurre a pesar de la existencia de políticas de contraseñas. La mayoría de las personas/empleados siguen las mismas reglas al crear contraseñas más complejas. Las contraseñas a menudo se crean relacionadas estrechamente con el servicio utilizado. Esto significa que muchos empleados a menudo seleccionan contraseñas que pueden tener el nombre de la empresa en las contraseñas. Las preferencias e intereses de una persona también juegan un papel significativo. Estos pueden ser mascotas, amigos, deportes, pasatiempos y muchos otros elementos de la vida. La recolección de información `OSINT` puede ser muy útil para descubrir más sobre las preferencias de un usuario y puede ayudar con la adivinanza de contraseñas. Se puede encontrar más información sobre OSINT en el módulo [OSINT: Corporate Recon](https://academy.hackthebox.com/course/preview/osint-corporate-recon). Comúnmente, los usuarios usan las siguientes adiciones para que su contraseña se ajuste a las políticas de contraseñas más comunes:

|**Description**|**Password Syntax**|
|---|---|
|First letter is uppercase.|`Password`|
|Adding numbers.|`Password123`|
|Adding year.|`Password2022`|
|Adding month.|`Password02`|
|Last character is an exclamation mark.|`Password2022!`|
|Adding special characters.|`P@ssw0rd2022!`|

Considerando que muchas personas quieren mantener sus contraseñas lo más simples posible a pesar de las políticas de contraseñas, podemos crear reglas para generar contraseñas débiles. Basándonos en estadísticas proporcionadas por [WPengine](https://wpengine.com/resources/passwords-unmasked-infographic/), la mayoría de las longitudes de contraseñas son `not longer` que `ten` caracteres. Entonces, lo que podemos hacer es seleccionar términos específicos que tengan al menos `five` caracteres de largo y que parezcan ser los más familiares para los usuarios, como los nombres de sus mascotas, pasatiempos, preferencias y otros intereses. Si el usuario elige una sola palabra (como el mes actual), agrega el `current year`, seguido de un carácter especial, al final de su contraseña, alcanzaríamos el requisito de contraseña de `ten-character`. Considerando que la mayoría de las empresas requieren cambios regulares de contraseña, un usuario puede modificar su contraseña simplemente cambiando el nombre de un mes o un solo número, etc. Usemos un ejemplo simple para crear una lista de contraseñas con solo una entrada.

### Password List

```r
cat password.list

password
```

Podemos usar una herramienta muy poderosa llamada [Hashcat](https://hashcat.net/hashcat/) para combinar listas de nombres y etiquetas potenciales con reglas de mutación específicas para crear wordlists personalizadas. Para familiarizarse más con Hashcat y descubrir todo su potencial, recomendamos el módulo [Cracking Passwords with Hashcat](https://academy.hackthebox.com/course/preview/cracking-passwords-with-hashcat). Hashcat utiliza una sintaxis específica para definir caracteres y palabras y cómo pueden modificarse. La lista completa de esta sintaxis se puede encontrar en la [documentation](https://hashcat.net/wiki/doku.php?id=rule_based_attack) oficial de Hashcat. Sin embargo, las que se enumeran a continuación son suficientes para entender cómo Hashcat muta las palabras.

|**Function**|**Description**|
|---|---|
|`:`|Do nothing.|
|`l`|Lowercase all letters.|
|`u`|Uppercase all letters.|
|`c`|Capitalize the first letter and lowercase others.|
|`sXY`|Replace all instances of X with Y.|
|`$!`|Add the exclamation character at the end.|

Cada regla se escribe en una nueva línea que determina cómo debe mutarse la palabra. Si escribimos las funciones mostradas anteriormente en un archivo y consideramos los aspectos mencionados, este archivo puede verse así:

### Hashcat Rule File

```r
cat custom.rule

:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
```

Hashcat aplicará las reglas de `custom.rule` para cada palabra en `password.list` y almacenará la versión mutada en nuestro `mut_password.list` en consecuencia. Por lo tanto, una palabra dará como resultado quince palabras mutadas en este caso.

### Generating Rule-based Wordlist

```r
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
cat mut_password.list

password
Password
passw0rd
Passw0rd
p@ssword
P@ssword
P@ssw0rd
password!
Password!
passw0rd!
p@ssword!
Passw0rd!
P@ssword!
p@ssw0rd!
P@ssw0rd!
```

`Hashcat` y `John` vienen con listas de reglas preconstruidas que podemos usar para nuestros propósitos de generación y cracking de contraseñas. Una de las reglas más utilizadas es `best64.rule`, que a menudo puede dar buenos resultados. Es importante tener en cuenta que el cracking de contraseñas y la creación de wordlists personalizadas es, en la mayoría de los casos, un juego de adivinanzas. Podemos reducir esto y realizar adivinanzas más dirigidas si tenemos información sobre la política de contraseñas y tomamos en cuenta el nombre de la empresa, la región geográfica, la industria y otros temas/palabras que los usuarios pueden seleccionar para crear sus contraseñas. Las excepciones son, por supuesto, casos en los que se filtran y encuentran contraseñas.

### Hashcat Existing Rules

```r
ls /usr/share/hashcat/rules/

best64.rule                  specific.rule
combinator.rule              T0XlC-insert_00-99_1950-2050_toprules_0_F.rule
d3ad0ne.rule                 T0XlC-insert_space_and_special_0_F.rule
dive.rule                    T0XlC-insert_top_100_passwords_1_G.rule
generated2.rule              T0XlC.rule
generated.rule               T0XlCv1.rule
hybrid                       toggles1.rule
Incisive-leetspeak.rule      toggles2.rule
InsidePro-HashManager.rule   toggles3.rule
InsidePro-PasswordsPro.rule  toggles4.rule
leetspeak.rule               toggles5.rule
oscommerce.rule              unix-ninja-leetspeak.rule
rockyou-30000.rule
```

Ahora podemos usar otra herramienta llamada [CeWL](https://github.com/digininja/CeWL) para escanear posibles palabras del sitio web de la compañía y guardarlas en una lista separada. Luego podemos combinar esta lista con las reglas deseadas y crear una lista de contraseñas personalizada que tenga una mayor probabilidad de adivinar una contraseña correcta. Especificamos algunos parámetros, como la profundidad para explorar (`-d`), la longitud mínima de la palabra (`-m`), el almacenamiento de las palabras encontradas en minúsculas (`--lowercase`), así como el archivo donde queremos almacenar los resultados (`-w`).

### Generating Wordlists Using CeWL

```r
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
wc -l inlane.wordlist

326
```