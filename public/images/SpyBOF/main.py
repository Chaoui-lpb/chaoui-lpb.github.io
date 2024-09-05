import os

# Extensions d'images courantes
image_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff']

# Fonction pour renommer les fichiers
def rename_images_in_directory():
    # Liste tous les fichiers dans le répertoire courant
    for filename in os.listdir('.'):
        # Vérifie si c'est un fichier image
        if any(filename.lower().endswith(ext) for ext in image_extensions):
            # Remplace les espaces par des underscores dans le nom du fichier
            new_filename = filename.replace(' ', '_')
            # Si le nom change, on renomme le fichier
            if new_filename != filename:
                os.rename(filename, new_filename)
                print(f'Renamed: {filename} -> {new_filename}')

# Exécuter la fonction
rename_images_in_directory()
