from authorities.authority_init import authority
from user import User
from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15
from charm.schemes.abenc.abenc_maabe_yj14 import MAABE
from charm.toolbox.pairinggroup import *
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.toolbox.hash_module import Waters
from hashlib import sha256
from charm.core.engine.util import objectToBytes,bytesToObject
import os
import charm.toolbox.symcrypto
import asyncio



#--------------------------------------------------------------------------------------------------------

def generate_global_params():

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
async def main():

    generate_global_params()

    attr_auth1 = ['ONE@AUTH1','TWO@AUTH1','THREE@AUTH1','FOR@AUTH1','FIVE@AUTH1']
    attr_auth2 = ['ONE@AUTH2','TWO@AUTH2','THREE@AUTH2','FOR@AUTH2','FIVE@AUTH2']
    attr_auth3 = ['ONE@AUTH3','TWO@AUTH3','THREE@AUTH3','FOR@AUTH3','FIVE@AUTH3']


    auth1 = authority(group='SS512', auth_name="AUTH1", attributs=attr_auth1)
    auth2 = authority(group='SS512', auth_name="AUTH2", attributs=attr_auth2)
    auth3 = authority(group='SS512', auth_name="AUTH3", attributs=attr_auth3)


    user1_name="user1"
    user2_name="user2"
    user3_name="user3"

    user1_keys = []
    user2_keys = []
    user3_keys = []

    user1_keys.append(auth1.generate_keys_for_user(gid=user1_name))
    user2_keys.append(auth2.generate_keys_for_user(gid=user2_name))
    user3_keys.append(auth3.generate_keys_for_user(gid=user3_name))

    print("user 1 keys: ",user1_keys)
    print("user 2 keys: ",user2_keys)
    print("user 3 keys: ",user3_keys)


if __name__ == "__main__":
    asyncio.run(main())