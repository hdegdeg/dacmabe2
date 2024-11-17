import sys
from pathlib import Path
import json
import base64
from charm.toolbox.pairinggroup import *
from charm.core.engine.util import objectToBytes,bytesToObject
import os
# Ajouter le chemin du dossier `aiocoap` au chemin de recherche de Python
aiocoap_path = Path("/home/charm/workspace/python_projects/aiocoap")
sys.path.insert(0, str(aiocoap_path))
import aiocoap
import asyncio
import sqlite3
from hashlib import sha256
from aiocoap import *
from aiocoap import Context, Message, resource
from aiocoap.numbers.codes import Code
from aiocoap.oscore import BaseSecurityContext
import charm.toolbox.symcrypto
import ast
from typing import List, Tuple

class Sensor(resource.Resource):
    def __init__(self,group,actions):
        self.group = PairingGroup(group)
        self.actions = actions

        # Connexion à la base de données SQLite (la base sera créée si elle n'existe pas)
        self.base_path='/home/charm/workspace/python_projects/dacmabe'  
        self.db_path_user = os.path.join(self.base_path, 'databases/sensors', 'usensor_database.db')

        # S'assurer que le dossier existe
        os.makedirs(os.path.dirname(self.db_path_user), exist_ok=True)

        # Connexion à la base de données SQLite
        try:
            self.conn_with_bdd_sensor = sqlite3.connect(self.db_path_user)
            self.cursor_sensor = self.conn_with_bdd_sensor.cursor()
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
        except json.JSONDecodeError:
            print("Erreur lors du décodage du JSON")
        
        print(f"Event reçue : {event}")

        # Simuler la génération d'un token en fonction de l'URI
        if 'request-access-to-action' == event:

            action = data['action']
            credential = data['credential']
            response = self.check_access(credential=credential, action=action)

            return Message(code=Code.CONTENT, payload= response.encode('utf-8'))

#---------------------------------------------------------------------------------------------------------

#Init DATA BASE OF USER
    def init_bdd(self):
        """
        Initialise la table pour stocker les clés ABE si elle n'existe pas.
        """
        try:
            self.cursor_sensor.execute('''
            CREATE TABLE IF NOT EXISTS action_token_table (
                id INTEGER PRIMARY KEY, 
                action_name TEXT UNIQUE NOT NULL,
                rvo TEXT UNIQUE NOT NULL,
                key_value TEXT NOT NULL                                        
            )
            ''')
            self.conn_with_bdd_sensor.commit()

            self.cursor_sensor.execute('''
            CREATE TABLE IF NOT EXISTS sensor_shamir_params_table (
                id_obj TEXT PRIMARY KEY ,
                su1 TEXT UNIQUE NOT NULL,
                prime TEXT UNIQUE NOT NULL
            )
            ''')
            
            self.conn_with_bdd_sensor.commit()
 
            print("Table 'sensor_token_action_table' initialisée.")
        except sqlite3.Error as e:
            print(f"Erreur lors de la création de la table : {e}")
            raise

#Close DATA BASE OF USER
    def close_connection(self):
        """
        Ferme la connexion à la base de données.
        """
        if self.conn_with_bdd_sensor:
            self.conn_with_bdd_sensor.close()
            print("Connexion à la base de données fermée.")

#Request to generate token for actions
    async def request_to_generate_credentials_for_actions(self):
            # Création du contexte client
        protocol = await aiocoap.Context.create_client_context()

        # Préparation du message
        request = aiocoap.Message(code=aiocoap.POST, uri="coap://localhost:5683/call_fog")
        # Création d'un dictionnaire et conversion en JSON puis en bytes
        payload = {
            "actions": self.actions,
            "event": "generate-token-action"
        }
        request.payload = json.dumps(payload).encode('utf-8')
    
        # Envoi de la requête
        response = await protocol.request(request).response

        server_response = response.payload.decode('utf-8')

        decoded_response = json.loads(server_response)

        id_obj = decoded_response['id_obj']
        SU1 = decoded_response['SU1']
        PRIME = decoded_response['PRIME']

        #insert Action,Token,RVO in table action_token
        decoded_response["token_bytes"] = base64.b64decode(decoded_response["token_bytes"])
        tokens_of_action = bytesToObject(decoded_response["token_bytes"], self.group)

        #print("Réponse du serveur :", tokens_of_action)

        for ele in tokens_of_action:
            Token = tokens_of_action[ele][0]
            RVO = tokens_of_action[ele][1]
            
            
            #hashed_key = sha256(objectToBytes(Token, self.group)).digest()
            print("token of action (sensor): ",Token)
            key_byte = objectToBytes(Token, self.group)

            self.cursor_sensor.execute('INSERT INTO action_token_table (action_name, rvo, key_value) VALUES (?, ?, ?)', 
                                (ele, str(RVO), key_byte))
            
          
            # Commit des changements dans la base de données
            self.conn_with_bdd_sensor.commit()
            print("element inserted successfuly")

        #insert SU1,PRIME in table Shamir Params
        self.cursor_sensor.execute('INSERT INTO sensor_shamir_params_table (id_obj, su1, prime) VALUES (?, ?, ?)', 
                                (id_obj, str(SU1), str(PRIME)))  
        
        self.conn_with_bdd_sensor.commit()  
        
        #start server Sensor
        await self.start_server()

#start server
    async def start_server(self):
        # Création du serveur CoAP
        root = resource.Site()

        # Ajouter la ressource 'generate-test' et l'associer à la méthode 'render_post' de FogNode
        root.add_resource(['call_sensor'], self)

        # Création du contexte de sécurité (OSCORE)
        context = await Context.create_server_context(root, bind=("localhost", 5684))
        context.oscore = BaseSecurityContext()  # Assurez-vous de spécifier le bon répertoire de clés

        print("Serveur SENSOR en écoute...")

        # Maintenir le serveur actif
        await asyncio.get_running_loop().create_future()    

    def reconstruct_secret(self, shares: List[Tuple[int, int]], threshold: int, PRIME) -> int:
        def _lagrange_interpolation(x: int, x_s: List[int], y_s: List[int]) -> int:
            def _basis(j: int) -> int:
                num = 1
                den = 1
                for m in range(len(x_s)):
                    if m != j:
                        num = (num * (x - x_s[m])) % PRIME
                        den = (den * (x_s[j] - x_s[m])) % PRIME
                return num * pow(den, -1, PRIME) % PRIME  # Modulo inverse

            result = 0
            for j in range(len(y_s)):
                result = (result + y_s[j] * _basis(j)) % PRIME
            return result

        if len(shares) < threshold:
            raise ValueError("Not enough shares to reconstruct the secret!")
        x_s, y_s = zip(*shares)
        return _lagrange_interpolation(0, x_s, y_s)

    def check_access(self, credential, action):
        # Récupération du chemin de fichier depuis la base de données
        self.cursor_sensor.execute('SELECT * FROM action_token_table WHERE action_name = ?', (action,)) 
        row = self.cursor_sensor.fetchone() 
        
        print("Rows: ",row)
        print("action: ",row[1])
        action =row[1]
        RVO1 = row[2]
        Key = row[3]

        print("key on byte (sensor): ",Key)

        hashed_key = sha256(objectToBytes(Key, self.group)).digest()
        print("hashed key:",hashed_key)
        
        cipher = charm.toolbox.symcrypto.AuthenticatedCryptoAbstraction(hashed_key)
        result=cipher.decrypt(credential, associatedData='21345')

        print("result befor decoded: ",result)
        decoded_result = result.decode('utf-8')
        print("result: ",type(decoded_result))
        data_dict = ast.literal_eval(decoded_result)

        #-----------------------------------------------------------------------------------
        SU2 = ast.literal_eval(data_dict['SU2'])
        TC = int(data_dict['TC'])

        # Récupération du chemin de fichier depuis la base de données
        self.cursor_sensor.execute('SELECT * FROM sensor_shamir_params_table ') 
        row = self.cursor_sensor.fetchone() 

        print("fetched data ", row)
        fixed_x = 1
        SU1 = (fixed_x, int(row[1]))
        PRIME = int(row[2])

        # Sélectionner 3 parts pour reconstruire le secret
        shares = []
        shares.append(SU1)
        shares.append(SU2)

        print("shares: ",shares)
        selected_shares = shares[:2]
        SU = self.reconstruct_secret(shares=selected_shares, threshold=2, PRIME= PRIME)
        

        RVO2 = int(TC) ^ SU
        print("TC: ",TC)
        print("SU: ",SU)
        print("RVO1: ",RVO1)
        print("RVO2: ",RVO2)


        print("HAVE ACCES: ",int(RVO1)==int(RVO2))
        
         
        if int(RVO1)==int(RVO2):
            return "access granted"
        else:
            return "you don't have access"

async def main():

    sensor = Sensor(
        group='SS512', 
        actions=[
            "action1",
            "action2",
            "action3"
        ]
        )
    
    await sensor.request_to_generate_credentials_for_actions( )
    
    

    #server_response["token_bytes"] = base64.b64decode(server_response["token_bytes"]).decode('utf-8')

    #print("with decoded token in byte: ",encoded_res["token_bytes"])

if __name__ == "__main__":
    asyncio.run(main())