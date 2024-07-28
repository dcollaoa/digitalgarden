import re
import os

# Obtener la ruta del directorio en el que se encuentra el script
directory_path = os.path.dirname(os.path.abspath(__file__))

# Expresión regular para encontrar las imágenes
pattern = re.compile(r'!\[\[Pasted image (\d{14})\.png\]\]')

# Nueva ruta de formato
replacement_format = '![](screenshots/Pasted image \1.png)'

# Función para procesar un archivo
def process_file(file_path):
    try:
        # Leer el archivo
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        
        # Realizar el reemplazo
        updated_content = pattern.sub(replacement_format, content)
        
        # Verificar si se realizaron cambios
        if content != updated_content:
            print(f'Procesando {file_path}...')
            
            # Mostrar contenido original para depuración
            print('Contenido original:')
            print(content[:500])  # Muestra solo los primeros 500 caracteres
            
            # Mostrar contenido actualizado para depuración
            print('Contenido actualizado:')
            print(updated_content[:500])  # Muestra solo los primeros 500 caracteres
            
            # Guardar los cambios en el archivo
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(updated_content)
            
            print(f'Reemplazo completado en {file_path}')
        else:
            print(f'No se encontraron coincidencias en {file_path}')
    except Exception as e:
        print(f'Error procesando {file_path}: {e}')

# Recorrer todos los archivos en el directorio
for filename in os.listdir(directory_path):
    if filename.endswith('.md'):
        file_path = os.path.join(directory_path, filename)
        process_file(file_path)

print("Proceso completado en todos los archivos Markdown.")
