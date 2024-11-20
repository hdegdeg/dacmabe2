from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15
from charm.schemes.abenc.abenc_maabe_yj14 import MAABE
from charm.toolbox.pairinggroup import *
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.toolbox.hash_module import Waters
from hashlib import sha256
from charm.core.engine.util import objectToBytes,bytesToObject
import ast
import json
import os
import base64
import sqlite3
import charm.toolbox.symcrypto
import pickle



#--------------------------------------------------------------------------------------------------------

def store_global_params():

    group = PairingGroup('SS512')

    debug = False
    maabe = MaabeRW15(group)
    public_parameters = maabe.setup()

    
    # Vérifie et crée le dossier "/authority_params" s'il n'existe pas
    directory = "public_params"
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    # Convertir les valeurs en texte, y compris les fonctions `H` et `F` en chaînes de caractères
    params_serializable = {
        k: v if not callable(v) else "" for k, v in public_parameters.items()
    }
    
    # Sérialiser et stocker les paramètres dans des fichiers
    serialized_message = objectToBytes(params_serializable, group)
    with open(os.path.join(directory, "public_params.json"), 'wb') as file:
        file.write(serialized_message)
    	
    

#-----------------------------------------------------------------------------------------------------------------


store_global_params()



