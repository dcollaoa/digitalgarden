¡Bienvenido al módulo `Attacking Web Applications with Ffuf`!

Hay muchas herramientas y métodos para utilizar en el fuzzing/fuerza bruta de directorios y parámetros. En este módulo, nos centraremos principalmente en la herramienta [ffuf](https://github.com/ffuf/ffuf) para fuzzing web, ya que es una de las herramientas más comunes y fiables disponibles para fuzzing web.

Los siguientes temas serán discutidos:

- Fuzzing para directorios
- Fuzzing para archivos y extensiones
- Identificación de vhosts ocultos
- Fuzzing para parámetros PHP
- Fuzzing para valores de parámetros

Herramientas como `ffuf` nos proporcionan una manera automatizada y práctica para hacer fuzzing en los componentes individuales de una aplicación web o una página web. Esto significa, por ejemplo, que usamos una lista que se utiliza para enviar solicitudes al servidor web si la página con el nombre de nuestra lista existe en el servidor web. Si obtenemos un código de respuesta 200, entonces sabemos que esta página existe en el servidor web, y podemos revisarla manualmente.