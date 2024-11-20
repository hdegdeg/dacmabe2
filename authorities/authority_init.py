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

class authority:
    def __init__(self,group,auth_name,attributs):

        self.auth_name = auth_name
        self.attributs = attributs

        self.group = PairingGroup(group)
        self.maabe = MaabeRW15(self.group)
        self.global_parameters = self.get_global_public_params()


        # Définition des attributs
        attributes1 = ['ONE', 'TWO']
        attributes2 = ['THREE', 'FOUR']

        # Configuration de l'authentification et génération des clés
        (self.public_key, self.secret_key) = self.maabe.authsetup(self.global_parameters, self.auth_name)
        self.store_public_params_with_functions(self.auth_name,self.public_key,self.secret_key)

        
        
        """
        # Dictionnaire des clés publiques
        self.public_keys = {'UT': self.public_key1, 'OU': self.public_key2}
        """
        


#--------------------------------------------------------------------------------------------------------

    def store_public_params_with_functions(self,auth_name, public_keys, secret_key):
        
        # Vérifie et crée le dossier "/authority_params" s'il n'existe pas
        directory = f"authority_params/{auth_name}"
        if not os.path.exists(directory):
            os.makedirs(directory)
        
        with open(os.path.join(directory, "public_key.json"), 'wb') as file:
            file.write(objectToBytes(public_keys, self.group))
            
        with open(os.path.join(directory, "secret_key.json"), 'wb') as file:
            file.write(objectToBytes(secret_key, self.group))
            
        
    	
    

#-----------------------------------------------------------------------------------------------------------------
    def get_global_public_params(self):
            with open('public_params/public_params.json','r') as file:
                params = file.read()
                orig_params = bytesToObject(params, self.group)

                # Remplacer les lambdas fictives H et F par des lambdas fonctionnelles
                orig_params['H'] = lambda x: self.group.hash(x, G2)
                orig_params['F'] = lambda x: self.group.hash(x, G2)
                
                
            return orig_params


    def generate_keys_for_user(self, gid):
        user_keys1 = self.maabe.multiple_attributes_keygen(self.global_parameters, self.secret_key, gid, self.attributs)

        return user_keys1


    """
	gid = "bob"
	user_attributes1 = ['STUDENT@UT', 'PHD@UT']
	user_attributes2 = ['STUDENT@OU']
	user_keys1 = self.maabe.multiple_attributes_keygen(self.public_parameters, secret_key1, gid, user_attributes1)
	user_keys2 = self.maabe.multiple_attributes_keygen(self.public_parameters, secret_key2, gid, user_attributes2)
    """




