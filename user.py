import sys
from pathlib import Path
import json
import base64
from charm.toolbox.pairinggroup import *
from charm.core.engine.util import objectToBytes,bytesToObject
from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15
from charm.schemes.abenc.abenc_maabe_yj14 import MAABE
import aiocoap
import asyncio
import os
import sqlite3
from hashlib import sha256
import charm.toolbox.symcrypto
import sys
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes


# Ajouter le chemin du dossier `aiocoap` au chemin de recherche de Python
aiocoap_path = Path("/home/charm/workspace/python_projects/aiocoap")
sys.path.insert(0, str(aiocoap_path))


class User:
    def __init__(self,group):
        self.group = PairingGroup(group) 
        self.maabe = MaabeRW15(self.group)


        # Connexion à la base de données SQLite (la base sera créée si elle n'existe pas)
        self.base_path='/home/charm/workspace/python_projects/dacmabe'  
        self.db_path_user = os.path.join(self.base_path, 'databases/users', 'user_database.db')

        # Appel de la fonction 
        self.public_parameters, self.secret_key1, self.secret_key2 = self.get_public_params()

        # Setup d'un utilisateur et attribution des clés
        self.gid = "bob"
        self.user_attributes1 = ['STUDENT@UT', 'PHD@UT']
        self.user_attributes2 = ['STUDENT@OU']
        self.user_keys1 = self.maabe.multiple_attributes_keygen(self.public_parameters, self.secret_key1, self.gid, self.user_attributes1)
        self.user_keys2 = self.maabe.multiple_attributes_keygen(self.public_parameters, self.secret_key2, self.gid, self.user_attributes2)
        self.user_keys = {'GID': self.gid, 'keys': self.merge_dicts([self.user_keys1, self.user_keys2])}

        # S'assurer que le dossier existe
        os.makedirs(os.path.dirname(self.db_path_user), exist_ok=True)

        # Connexion à la base de données SQLite
        try:
            self.conn_with_bdd_user = sqlite3.connect(self.db_path_user)
            self.cursor_user = self.conn_with_bdd_user.cursor()
            self.init_bdd()  # Initialiser la base de données
        except sqlite3.Error as e:
            print(f"Erreur lors de la connexion à la base de données : {e}")
            raise
    

    
#---------------------------------------------------------------------------------------------------------

#Init DATA BASE OF USER
    def init_bdd(self):
        """
        Initialise la table pour stocker les clés ABE si elle n'existe pas.
        """
        try:
            self.cursor_user.execute('''
            CREATE TABLE IF NOT EXISTS access_token_user_table (
                id INTEGER PRIMARY KEY,
                obj_id INTEGER,
                action_name TEXT UNIQUE,
                key_value TEXT UNIQUE,
                tc TEXT, 
                su2 TEXT,
                index_session TEXT,
                session_id TEXT                                      
            )
            ''')
            self.conn_with_bdd_user.commit()

            print("Table 'sensor_token_action_table' initialisée.")
        except sqlite3.Error as e:
            print(f"Erreur lors de la création de la table : {e}")
            raise

#Close DATA BASE OF USER
    def close_connection(self):
        """
        Ferme la connexion à la base de données.
        """
        if self.conn_with_bdd_user:
            self.conn_with_bdd_user.close()
            print("Connexion à la base de données fermée.")

#MERGE Multiples Keys
    def merge_dicts(self,dict_args):
        """
        Given any number of dicts, shallow copy and merge into a new dict,
        precedence goes to key value pairs in latter dicts.
        """
        result = {}
        for dictionary in dict_args:
            result.update(dictionary)
        return result
    
 
#Get Public Parameters
    def get_public_params(self):
        with open(os.path.join(self.base_path, 'authority_params/public_params_auth.json'),'r') as file:
            params = file.read()
            orig_params = bytesToObject(params, self.group)

            # Remplacer les lambdas fictives H et F par des lambdas fonctionnelles
            orig_params['H'] = lambda x: self.group.hash(x, G2)
            orig_params['F'] = lambda x: self.group.hash(x, G2)
        
            
        with open(os.path.join(self.base_path, 'authority_params/secret_key1.json'), 'r') as file:
            secret_key1 = file.read()
            orig_secret_key1 = bytesToObject(secret_key1, self.group)
        
        with open(os.path.join(self.base_path, 'authority_params/secret_key2.json'), 'r') as file:
            secret_key2 = file.read()
            orig_secret_key2 = bytesToObject(secret_key2, self.group)
            
        return orig_params, orig_secret_key1, orig_secret_key2

#Request credential of action from Fog
    async def request_credential_of_action(self,action):
        # Création du contexte client
        protocol = await aiocoap.Context.create_client_context()

        # Préparation du message
        request = aiocoap.Message(code=aiocoap.POST, uri="coap://localhost:5683/call_fog")
        # Création d'un dictionnaire et conversion en JSON puis en bytes
        payload = {
            "action":action,
            "id_obj":"2007704412",
            "event": "generate-credential-user"
        }
        request.payload = json.dumps(payload).encode('utf-8')
    
        # Envoi de la requête
        response = await protocol.request(request).response

        server_response = response.payload.decode('utf-8')

        print("server_response:",server_response)

        decoded_response = json.loads(server_response)

        decoded_response["token_bytes"] = base64.b64decode(decoded_response["token_bytes"])

        self.store_access_token(
            id_obj=decoded_response["id_obj"], 
            action=decoded_response["action"],
            su2=decoded_response["SU2"],
            tc=decoded_response["TC"],
            token=self.decrypt_token_for_action(key_value=decoded_response["token_bytes"])
            )

        return decoded_response

#Decypte token with MA-ABE
    def decrypt_token_for_action(self,key_value):
        
        # Lire le fichier et afficher le contenu
        orig_cipher = bytesToObject(key_value, self.group)
            
        # Déchiffrement avec MA-ABE
        decrypted_message = self.maabe.decrypt(self.public_parameters, self.user_keys, orig_cipher)
        
        
        return decrypted_message

#Store Decrypted Key
    def store_access_token(self,token, action, id_obj,tc,su2):
        # Sérialisation du message
        serialized_message = objectToBytes(token, self.group)
        
        print("token of (USER): ",token)
        print("token on byte (USER): ",serialized_message)

        # Récupération du chemin de fichier depuis la base de données
        self.cursor_user.execute('SELECT * FROM access_token_user_table WHERE action_name = ?', (f"{id_obj}_{action}",)) 
        rows = self.cursor_user.fetchone() 
        
        
        if rows:
            print("key found in database")
        else:
            self.cursor_user.execute('INSERT INTO access_token_user_table (obj_id, action_name, key_value, tc, su2) VALUES (?, ?, ?, ?, ?)', 
                                (id_obj, action, serialized_message,str(tc), str(su2)))

            print("have been successfully stored")
            
            # Commit des changements dans la base de données
            self.conn_with_bdd_user.commit()

#Store Decrypted Key
    async def request_session_id_for_action(self, action, obj_id):
        payload = {
            "action":action,
            "event":"generate-session-id"
        }
        
        response_server = await self.post_request(port='5684', path='call_sensor', payload=payload)
        print("payload: ",response_server.payload)
        
        if(response_server.payload):
                server_response = response_server.payload.decode('utf-8')

                print("server_response:",server_response)

                decoded_response = json.loads(server_response)
        
                
                print("index: ",decoded_response['index'])
                print("index: ",decoded_response['session_id'])

                
                index = decoded_response['index']
                session_id = decoded_response['session_id']
                session_id = eval(session_id)

                print("session id: ",session_id)
                print("type: ",type(session_id))

                self.cursor_user.execute('update access_token_user_table set index_session=?, session_id=? WHERE action_name = ? and obj_id=?', (index, session_id, action, obj_id))
                self.conn_with_bdd_user.commit()

                return True
                
        return False

#-----------------------------------------------------------------------------------------  SYMETRIC ENCRYPTION
    def symetric_encryption(self, mod, data, key, nonce):
        # Transformation du numéro de session en nonce de 15 octets
        #nonce = nonce.to_bytes(15, byteorder='big', signed=False)

        # Initialisation du chiffrement AES en mode OCB
        cipher = AES.new(key, mod, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())

        return ciphertext, tag

    def symetric_decryption(self, mod, ciphertext, tag, key, nonce):
        # Transformation du numéro de session en nonce de 15 octets
        #nonce = nonce.to_bytes(15, byteorder='big', signed=False)

        cipher = AES.new(key, mod, nonce=nonce)
        try:
            message = cipher.decrypt_and_verify(ciphertext, tag)
            return message
        except ValueError:
            return "The message was modified!" 

#-----------------------------------------------------------------------------------------           

  
    async def request_access_to_action(self,action):
        id_obj = 0
        token = ''
        TC = 0
        SU2 = 0
        # Récupération du chemin de fichier depuis la base de données
        self.cursor_user.execute('SELECT * FROM access_token_user_table WHERE action_name = ?', (action,)) 
        rows = self.cursor_user.fetchone()  

        
        print("Rows: ",rows)
        

        if rows == None :
            print("credentials dosn't exist")
            response = await self.request_credential_of_action(action=action)
            decrypted_token = self.decrypt_token_for_action(response['token_bytes'])

            if decrypted_token:
                print("get credential and try to access")
                await self.request_access_to_action(action)

        elif rows !=None and rows[6] == None:
             id_obj = rows[1]
             is_generated = await self.request_session_id_for_action(action=action, obj_id=id_obj)
             
             if is_generated:
                await self.request_access_to_action(action)
             else: 
                 print("can't generate session id")
                 return 

        elif rows !=None:  # Indentation correcte ici
            
            id_obj = rows[1]
            #action = row[2]
            token = rows[3]
            TC = rows[4]
            SU2 = rows[5]
            index_session = rows[6]
            session_id = rows[7]

            credential = {
                "SU2":SU2,
                "TC":TC,
            }

            hashed_key = sha256(objectToBytes(token, self.group)).digest()
            
            print("token from BDD (USER): ",token)

            

            # Utiliser ast.literal_eval pour convertir depuis TEXT to Byte reèl
            #byte_value = eval(session_id)

            # Utiliser base64 pour interpréter le contenu de manière sécurisée
            #base64_value = base64.b64encode(byte_value).decode('utf-8')

            print("--------------------------------------session ID: ",session_id)

            cipher_text,tag = self.symetric_encryption(data=str(credential), key=hashed_key, nonce=session_id, mod=AES.MODE_GCM)
            
            """
            cipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(hashed_key)
            ciphertextAssociatedData = cipher.encrypt(str(credential), associatedData=session_id,)
            """

            payload = {
                "id_obj":id_obj,
                "action":action,
                "index_session":index_session,
                "credential":str(cipher_text),
                "tag":str(tag),
                "event":'request-access-to-action'
            }
            print("cipher: ",cipher_text)
            print("tag: ",tag )

            #call sensor server
            response_server = await self.post_request(port='5684', path='call_sensor', payload=payload)

            if(response_server.payload):
                decoded_rep = response_server.payload.decode('utf-8')

                if decoded_rep=='access granted': 

                    new_session_id = sha256(session_id).digest()
                    print("after hash :",new_session_id)

                    
                    self.cursor_user.execute('update access_token_user_table set session_id=? WHERE index_session = ?', (new_session_id, int(index_session))) 
                    is_updated = self.conn_with_bdd_user.commit()
                    print("data updated :",is_updated)
                    

                print("SENSOR RESPONSE: ",decoded_rep)
        #-----------------------------------------------------------------------------------
        """
        result=cipher.decrypt(ciphertextAssociatedData, associatedData='4545')
        print(result)
        """
    
    async def post_request(self, port, path, payload):
        #-----------------------------------------------------------------------------------
            # Création du contexte client
            protocol = await aiocoap.Context.create_client_context()
            uri = f"coap://localhost:{port}/{path}"
            print("URI: ",uri)
            # Préparation du message
            request = aiocoap.Message(code=aiocoap.POST, uri=uri)
            
            request.payload = json.dumps(payload).encode('utf-8')
        
            # Envoi de la requête
            response = await protocol.request(request).response

            print("response: ",response)

            return response

async def main():

    user = User('SS512')
    """
    
    """
    #print("decrypted_toekn :", decrypted_token)

    await user.request_access_to_action(action="action3")
    """
    group = PairingGroup('SS512')

    tokens = bytesToObject(decoded_response["token_bytes"], group)
    print("Decoded binary_data:", tokens)
  
    """
    #server_response["token_bytes"] = base64.b64decode(server_response["token_bytes"]).decode('utf-8')

    #print("with decoded token in byte: ",encoded_res["token_bytes"])

if __name__ == "__main__":
    asyncio.run(main())