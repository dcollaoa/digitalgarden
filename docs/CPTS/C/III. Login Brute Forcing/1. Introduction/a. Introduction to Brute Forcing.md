Un ataque de [Brute Force](https://en.wikipedia.org/wiki/Brute-force_attack) es un método que intenta adivinar contraseñas o claves mediante sondeos automatizados. Un ejemplo de un ataque de fuerza bruta es el cracking de contraseñas. Las contraseñas generalmente no se almacenan en texto claro en los sistemas, sino como valores hash.

Aquí hay una pequeña lista de archivos que pueden contener contraseñas hasheadas:

|**`Windows`**|**`Linux`**|
|---|---|
|unattend.xml|shadow|
|sysprep.inf|shadow.bak|
|SAM|password|

Dado que la contraseña no puede calcularse hacia atrás desde el valor hash, el método de fuerza bruta determina los valores hash pertenecientes a las contraseñas seleccionadas aleatoriamente hasta que un valor hash coincide con el valor hash almacenado. En este caso, se encuentra la contraseña. Este método también se llama offline brute-forcing. Este módulo se centrará en el brute-forcing en línea y tratará explícitamente con los formularios de inicio de sesión de los sitios web.

En la mayoría de los sitios web, siempre hay un área de inicio de sesión para administradores, autores y usuarios en algún lugar. Además, los nombres de usuario a menudo son reconocibles en las páginas web, y las contraseñas complejas rara vez se usan porque son difíciles de recordar. Por lo tanto, vale la pena utilizar el método de brute forcing en línea después de una enumeración adecuada si no pudimos identificar ningún punto de apoyo inicial.

Hay muchas herramientas y métodos para utilizar en el brute-forcing de inicio de sesión, como:

- `Ncrack`
- `wfuzz`
- `medusa`
- `patator`
- `hydra`
- y otros.

En este módulo, utilizaremos principalmente `hydra`, ya que es una de las herramientas más comunes y confiables disponibles.

Los siguientes temas serán discutidos:

- Brute forcing básico de autenticación HTTP
- Brute force para contraseñas predeterminadas
- Brute forcing de formularios de inicio de sesión
- Brute force de nombres de usuario
- Creación de listas personalizadas de nombres de usuario y contraseñas basadas en nuestro objetivo
- Brute forcing de inicios de sesión de servicios, como FTP y SSH