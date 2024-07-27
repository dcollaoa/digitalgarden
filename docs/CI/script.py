import os
import re

# Expresión regular para encontrar el patrón ![[numero.nombre.srt]]
pattern = re.compile(r'!\[\[\d+\.\s*[^]]+\.srt\]\]')

def remove_pattern_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        
        # Elimina todas las ocurrencias del patrón
        new_content = pattern.sub('', content)
        
        if new_content != content:
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(new_content)
            print(f"Actualizado {file_path}")
    except Exception as e:
        print(f"Error al procesar {file_path}: {e}")

def process_directory(directory):
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isdir(file_path):
            # Si es un directorio, llama recursivamente
            process_directory(file_path)
        elif filename.endswith('.md'):
            # Procesa archivos .md
            remove_pattern_from_file(file_path)

# Obtén el directorio actual
root_directory = os.getcwd()

# Procesa el directorio raíz y todos los subdirectorios
process_directory(root_directory)
