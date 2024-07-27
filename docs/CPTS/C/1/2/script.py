import os
import re

# Mapea letras a números
letter_to_number = {
    'a': 1, 'b': 2, 'c': 3, 'd': 4, 'e': 5, 'f': 6, 'g': 7, 'h': 8, 'i': 9, 'j': 10,
    'k': 11, 'l': 12, 'm': 13, 'n': 14, 'o': 15, 'p': 16, 'q': 17, 'r': 18, 's': 19,
    't': 20, 'u': 21, 'v': 22, 'w': 23, 'x': 24, 'y': 25, 'z': 26
}

# Obtén el directorio actual
directory = os.getcwd()

for filename in os.listdir(directory):
    if filename.endswith('.md'):
        # Extrae la primera letra del archivo (en minúsculas)
        first_letter = re.sub(r'[^a-zA-Z]', '', filename[0]).lower()
        
        # Obtiene el número correspondiente a la letra
        number = letter_to_number.get(first_letter, None)
        
        if number is not None:
            # Crea el nuevo nombre del archivo
            new_filename = f"{number}.md"
            # Renombra el archivo
            os.rename(os.path.join(directory, filename), os.path.join(directory, new_filename))
            print(f"Renombrado {filename} a {new_filename}")
        else:
            print(f"No se puede mapear la letra '{first_letter}' para el archivo {filename}")
