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
import random
from typing import List, Tuple
from sympy import randprime
import sys
from pathlib import Path
import asyncio
from aiocoap import *
from aiocoap import Context, Message, resource
from aiocoap.numbers.codes import Code
from aiocoap.oscore import BaseSecurityContext
import sys
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

# Ajouter le chemin du dossier `aiocoap` au chemin de recherche de Python
aiocoap_path = Path("/home/charm/workspace/python_projects/aiocoap")
sys.path.insert(0, str(aiocoap_path))

class FogNode(resource.Resource):
    def __init__(self, group: str, authorities=[], node_name=''):
        """
        Initialisation du nœud Fog avec le schéma MA-ABE et une base de données SQLite.
        """

        # Définir le chemin de la base de données
        self.base_path = '/home/charm/workspace/python_projects/dacmabe'
        db_path = os.path.join(self.base_path, f'databases/fogs/{node_name}', 'fog_database.db')


        # Initialisation du groupe et du schéma MA-ABE
        self.group = PairingGroup(group)
        self.maabe = MaabeRW15(self.group)

        # Appel de la fonction
        self.public_parameters = self.get_public_params()
        
        self.authaurities_keys = {}
        for auth in authorities:
            self.authaurities_keys[auth] = self.get_public_keys(auth_name=auth)
           


        access_policy1='(ONE@AUTH1 or THREE@AUTH2) and (ONE@AUTH2 or TWO@AUTH3)'
        access_policy2='(ONE@AUTH2 or TWO@AUTH3) and (FOR@AUTH1 or THREE@AUTH2)'
        access_policy3='(FIVE@AUTH3 or FOR@AUTH1) and (ONE@AUTH1 or FIVE@AUTH2)'

        self.access_policies = [access_policy1, access_policy2, access_policy3]
        # S'assurer que le dossier existe
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        # Connexion à la base de données SQLite
        try:
            self.conn_with_bdd_fog = sqlite3.connect(db_path)
            self.cursor_fog = self.conn_with_bdd_fog.cursor()
            self.init_bdd()  # Initialiser la base de données
        except sqlite3.Error as e:
            print(f"Erreur lors de la connexion à la base de données : {e}")
            raise
    
    async def render_post(self, request):
        """
        Méthode générique pour traiter différentes actions.
        """
        
        decodedDATA = request.payload.decode()
        print("payload: ", decodedDATA)


        # Convertir la chaîne JSON en dictionnaire
        try:
            data = json.loads(decodedDATA)
            event = data['event']
            tag = eval(data['tag'])

            cipher_byte = eval(data['cipher'])

            data = self.symetric_decryption(ciphertext=cipher_byte, mod=AES.MODE_GCM, tag=tag, with_static_key=True)
            data = eval(data)
          
            
        except json.JSONDecodeError:
            print("Erreur lors du décodage du JSON")


  
        print(f"Event reçue : {event}")

        # Simuler la génération d'un token en fonction de l'URI
        if 'generate-token-action' == event:
            actions_list = data['actions']
            
            (action_token_dict, SU1, PRIME, id_obj) = self.generate_token_for_action(actions_list)
            
            #Convert token to byte,
            tokens_of_actions_bytes = objectToBytes(action_token_dict, self.group)
            print("action_token_dict: ",action_token_dict)

            credentials_of_sensor = {
                "token_bytes":tokens_of_actions_bytes,
                "SU1":SU1,
                "PRIME":PRIME,
                "id_obj":id_obj
            }
            
            
            credentials_of_sensor["token_bytes"] = base64.b64encode(credentials_of_sensor["token_bytes"]).decode('utf-8')

            credentials_of_sensor_bytes = json.dumps(credentials_of_sensor).encode('utf-8')

            encrypted_data,tag = self.symetric_encryption(data=credentials_of_sensor_bytes, mod=AES.MODE_GCM, with_static_key=True)

            server_response = {
                "cipher":str(encrypted_data),
                "tag":str(tag)
            }

            encoded_res =  json.dumps(server_response).encode('utf-8')

            #request.payload = self.symetric_encryption(data=payload_to_json, mod=AES.MODE_GCM, with_static_key=True)

            return Message(code=Code.CONTENT, payload= encoded_res)

        elif 'generate-credential-user' == event:
            action = data['action']
            id_obj = data['id_obj']
            (SU2, TC, action_token_dict) = self.generate_credential_for_user(action=action, id_obj=id_obj)
            
            print("SU2: ",SU2)
            credentials_of_sensor = {
                "SU2":str(SU2),
                "TC":TC,
                "token_bytes":action_token_dict,
                "id_obj":id_obj,
                "action":action,
            }

            credentials_of_sensor["token_bytes"] = base64.b64encode(credentials_of_sensor["token_bytes"]).decode('utf-8')

            credentials_of_sensor_bytes = json.dumps(credentials_of_sensor).encode('utf-8')

            encrypted_data,tag = self.symetric_encryption(data=credentials_of_sensor_bytes, mod=AES.MODE_GCM, with_static_key=True)

            server_response = {
                "cipher":str(encrypted_data),
                "tag":str(tag)
            }

            encoded_res =  json.dumps(server_response).encode('utf-8')

            return Message(code=Code.CONTENT, payload= encoded_res)
        

        else:
            print("URI non reconnue")
            return Message(code=Code.BAD_REQUEST, payload="Action non supportée")

        # Simuler la génération d'un token
        print(f"Token généré: {token}")
        
        # Retourner une réponse au client
        return Message(code=Code.CONTENT, payload=token.encode())

    def init_bdd(self):
        """
        Initialise la table pour stocker les clés ABE si elle n'existe pas.
        """
        try:
            self.cursor_fog.execute('''
            CREATE TABLE IF NOT EXISTS sensor_token_action_table (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                obj_id TEXT NOT NULL,
                action_name TEXT UNIQUE NOT NULL,
                rvo TEXT UNIQUE NOT NULL,
                key_value TEXT NOT NULL
            )
            ''')
            self.conn_with_bdd_fog.commit()

            self.cursor_fog.execute('''
            CREATE TABLE IF NOT EXISTS sensor_shamir_params_table (
                obj_id TEXT PRIMARY KEY ,
                su1 TEXT UNIQUE NOT NULL,
                prime TEXT UNIQUE NOT NULL
            )
            ''')
            
            self.conn_with_bdd_fog.commit()
            print("Table 'sensor_token_action_table' initialisée.")
        except sqlite3.Error as e:
            print(f"Erreur lors de la création de la table : {e}")
            raise

    def close_connection(self):
        """
        Ferme la connexion à la base de données.
        """
        if self.conn_with_bdd_fog:
            self.conn_with_bdd_fog.close()
            print("Connexion à la base de données fermée.")
    
    def get_public_params(self):
        with open(os.path.join(self.base_path, 'public_params/public_params.json'),'r') as file:
            params = file.read()
            orig_params = bytesToObject(params, self.group)

            # Remplacer les lambdas fictives H et F par des lambdas fonctionnelles
            orig_params['H'] = lambda x: self.group.hash(x, G2)
            orig_params['F'] = lambda x: self.group.hash(x, G2)    
            
        return orig_params
    
    def get_public_keys(self,auth_name):

        path_file = f'authority_params/{auth_name}/public_key.json'
        
        with open(os.path.join(self.base_path, path_file), 'r') as file:
            public_keys = file.read()
            orig_public_keys = bytesToObject(public_keys, self.group)
            
            
        return orig_public_keys


#-----------------------------------------------------------GENERATE TOKENS FOR ACTIONS----------------------------------------------------    
    def generate_token_for_action(self,actions):
        
        id_obj=random.getrandbits(32)
        #id_obj = 2007704412
        #access_policy= random.choice(self.access_policies) 
        action_token_dict={}

        #-----------------------------------Generate tokens and random values for every action
        # Parcourir la liste des actions
        for action in actions:
            # Génération du message aléatoire
            message1 = self.group.random(GT)
            # Générer une valeur aléatoire de 256 bits
            RVO = random.getrandbits(256)
            
            # Chiffrement du message avec MA-ABE
            access_policy= random.choice(self.access_policies) 
            public_k = self.get_public_keys("AUTH1")

            print("public key: ",public_k)
            print("type: ",type(public_k))
            print("type egga: ",type(public_k['egga']))

            

            cipher_text = self.maabe.encrypt(self.public_parameters, self.authaurities_keys, message1, access_policy)

            serialized_message = objectToBytes(cipher_text, self.group)

            print("have ben seralized")
            
            # Ajouter au dictionnaire le tuple (message1, RVO)
            self.cursor_fog.execute(
                'INSERT INTO sensor_token_action_table (obj_id, action_name, rvo,key_value) VALUES (?, ?, ?, ?)',
                (id_obj, f"{id_obj}_{action}", str(RVO), serialized_message)
            )

            # Ajouter au dictionnaire le tuple (message1, RVO)
            action_token_dict[action] = (message1, RVO)

        #-----------------------------------generate params of SHAMIR SECRET SHARING
        PRIME = randprime(10**100, 10**101)
        SU1 = random.getrandbits(256)
        self.cursor_fog.execute(
                'INSERT INTO sensor_shamir_params_table (obj_id,su1,prime) VALUES (?,?, ?)',
                (id_obj,str(SU1), str(PRIME))
            )
        
        # Commit des changements dans la base de données
        self.conn_with_bdd_fog.commit()

        return action_token_dict ,SU1 ,PRIME,id_obj

#-----------------------------------------------------------CREATE SHARE FOR USER----------------------------------------------------    

    def generate_coefficients(self,secret, fixed_share, PRIME) -> List[int]:

        """
        Génère les coefficients du polynôme de Shamir en fixant une part spécifique.
        """
        x_fixed, y_fixed = fixed_share
        # Le terme constant est le secret
        c0 = secret
        # Le coefficient suivant est calculé pour que f(x_fixed) = y_fixed
        c1 = (y_fixed - c0) % PRIME
        return [c0, c1]

    def create_shares(self,secret: int, fixed_share: Tuple[int, int], total_shares: int, PRIME:int) -> List[Tuple[int, int]]:
        """
        Génère les parts du secret en fixant une part et en générant les autres dynamiquement.
        """
        coefficients = self.generate_coefficients(secret=secret, fixed_share=fixed_share, PRIME=PRIME)
        shares = [fixed_share]
        for x in range(1, total_shares + 1):
            if x == fixed_share[0]:
                continue  # Sauter la part fixe
            # Évaluer le polynôme à x
            y = sum(coeff * (x**exp) for exp, coeff in enumerate(coefficients)) % PRIME
            shares.append((x, y))
        return shares

#-----------------------------------------------------------GET CREDENTIALS FOR ACTION----------------------------------------------------    
    def get_credential_of_action(self, action, id_obj):
        Token = 0
        RVO = 0
        SU1 = 0
        PRIME = 0
        # Get TOken and RVO of action
        self.cursor_fog.execute('SELECT * FROM sensor_token_action_table WHERE action_name = ?', (f"{id_obj}_{action}",)) 
        rows = self.cursor_fog.fetchone()  

        if rows:
            RVO =  rows[3]
            Token = rows[4]

        else:
            print("Aucun résultat trouvé pour l'action spécifiée.")

        # Get SU1 AND Prime of sensor
        self.cursor_fog.execute('SELECT * FROM sensor_shamir_params_table WHERE obj_id = ?', (id_obj,)) 
        rows = self.cursor_fog.fetchone()  

        if rows:
            SU1 = rows[1]
            PRIME = rows[2]
        else:
            print("Aucun résultat trouvé pour l'action spécifiée.")
        
        print("-------Token: ",Token," \n\n-----RVO: ",RVO,"\n\n----SU1: ",SU1 ,"\n\n---PRIME: ",PRIME)
        return Token, RVO, SU1, PRIME
    

#-----------------------------------------------------------GENERATE CREDENTIALS FOR USER----------------------------------------------------    
    def generate_credential_for_user(self,id_obj, action):
        Token, RVO, SU1, PRIME= self.get_credential_of_action(action=action, id_obj=id_obj)

        #--------------------------------------------------------------Generate Random share SU
        SU = random.getrandbits(256)

        #--------------------------------------------------------------Calculate Cached RVO
        TC = int(RVO) ^ SU
 
        #--------------------------------------------------------------Partage the Secret SU
        fixed_x = 1
        SU1 = int(SU1)

        fixed_shared = (fixed_x, SU1)

        generated_shares = self.create_shares(secret=SU, fixed_share=fixed_shared, total_shares=2, PRIME=int(PRIME))

        SU2 = [ele for ele in generated_shares if ele[0]==2]
        

        return  SU2[0], TC, Token

#-----------------------------------------------------------------------------------------  SYMETRIC ENCRYPTION
    def symetric_encryption(self, mod, data, key='', nonce='', with_static_key=False):

        if with_static_key:
            with open("keys/symtric_key.bin", "rb") as f:
                nonce = f.read(15)
                key = f.read()
        # Transformation du numéro de session en nonce de 15 octets
        #nonce = nonce.to_bytes(15, byteorder='big', signed=False)

        # Initialisation du chiffrement AES en mode OCB
        cipher = AES.new(key, mod, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        return ciphertext, tag

    def symetric_decryption(self, mod, ciphertext, tag, key='', nonce='', with_static_key=False):

        if with_static_key:
            with open("keys/symtric_key.bin", "rb") as f:
                nonce = f.read(15)
                key = f.read()

        # Transformation du numéro de session en nonce de 15 octets
        #nonce = nonce.to_bytes(15, byteorder='big', signed=False)

        cipher = AES.new(key, mod, nonce=nonce)
        try:
            print("-----------------------------------------------before decrypt")
            message = cipher.decrypt_and_verify(ciphertext, tag)
            return message
        except ValueError:
            return "The message was modified!" 

#-----------------------------------------------------------------------------------------    

    async def init_node(self,port):
        # Création du serveur CoAP
        root = resource.Site()

        # Ajouter la ressource 'generate-test' et l'associer à la méthode 'render_post' de FogNode
        root.add_resource(['call_fog'], self)

        # Création du contexte de sécurité (OSCORE)
        context = await Context.create_server_context(root, bind=("localhost", port))
        context.oscore = BaseSecurityContext()  # Assurez-vous de spécifier le bon répertoire de clés

        print("Serveur Fog en écoute...")

        # Maintenir le serveur actif
        await asyncio.get_running_loop().create_future()


async def main():


    aes_key = get_random_bytes(16)

    static_nonce=123456789
    nonce = static_nonce.to_bytes(15, byteorder='big', signed=False)

    # S'assurer que le dossier existe
    is_exist = os.makedirs(os.path.dirname("keys/symtric_key.bin"), exist_ok=True)
    print("file exist")
    
    if is_exist==False:
        with open("keys/symtric_key.bin", "wb") as f:
            f.write(aes_key)
            f.write(nonce)
    

    # creation of object FogNode 
    fog = FogNode(group='SS512',authorities=["AUTH1","AUTH2","AUTH3"], node_name="node1")
    await fog.init_node(port=5683)

    

if __name__ == "__main__":
    asyncio.run(main())
