from bson.binary import Binary
from bson.binary import STANDARD
from bson.codec_options import CodecOptions
from datetime import datetime
from pymongo import MongoClient
from pymongo.encryption import Algorithm
from pymongo.encryption import ClientEncryption
from pymongo.encryption_options import AutoEncryptionOpts
from pymongo.errors import EncryptionError, ServerSelectionTimeoutError, ConnectionFailure
from urllib.parse import quote_plus
import sys

# IN VALUES HERE!
PETNAME = 
MDB_PASSWORD = 
APP_USER = "app_user"
CA_PATH = "/etc/pki/tls/certs/ca.cert"

def mdb_client(connection_string, auto_encryption_opts=None):
  """ Returns a MongoDB client instance
  
  Creates a  MongoDB client instance and tests the client via a `hello` to the server
  
  Parameters
  ------------
    connection_string: string
      MongoDB connection string URI containing username, password, host, port, tls, etc
  Return
  ------------
    client: mongo.MongoClient
      MongoDB client instance
    err: error
      Error message or None of successful
  """

  try:
    client = MongoClient(connection_string)
    client.admin.command('hello')
    return client, None
  except (ServerSelectionTimeoutError, ConnectionFailure) as e:
    return None, f"Cannot connect to database, please check settings in config file: {e}"

def main():

  # Obviously this should not be hardcoded
  connection_string = "mongodb://%s:%s@csfle-mongodb-%s.mdbtraining.net/?serverSelectionTimeoutMS=5000&tls=true&tlsCAFile=%s" % (
    quote_plus(APP_USER),
    quote_plus(MDB_PASSWORD),
    PETNAME,
    quote_plus(CA_PATH)
  )

  # Declare or key vault namespce
  keyvault_db = "__encryption"
  keyvault_coll = "__keyVault"
  keyvault_namespace = f"{keyvault_db}.{keyvault_coll}"

  # declare our key provider type
  provider = "kmip"

  # declare our key provider attributes
  kms_provider = {
    provider: {
      "endpoint": f"csfle-kmip-{PETNAME}.mdbtraining.net"
    }
  }
  
  # declare our database and collection
  encrypted_db_name = "companyData"
  encrypted_coll_name = "employee"

  # instantiate our MongoDB Client object
  client, err = mdb_client(connection_string)
  if err is not None:
    print(err)
    sys.exit(1)


  # Instantiate our ClientEncryption object
  client_encryption = ClientEncryption(
    kms_provider,
    keyvault_namespace,
    client,
    CodecOptions(uuid_representation=STANDARD),
    kms_tls_options = {
      "kmip": {
        "tlsCAFile": "/etc/pki/tls/certs/ca.cert",
        "tlsCertificateKeyFile": "/home/ec2-user/server.pem"
      }
    }
  )

  auto_encryption = AutoEncryptionOpts(
    kms_provider,
    keyvault_namespace,
    schema_map = , # WHAT DO WE PUT HERE?
    bypass_auto_encryption = True, # we do not want to autoencrypt
    kms_tls_options = {
      "kmip": {
        "tlsCAFile": "/etc/pki/tls/certs/ca.cert",
        "tlsCertificateKeyFile": "/home/ec2-user/server.pem"
      }
    },
    crypt_shared_lib_required = True,
    mongocryptd_bypass_spawn = True,
    crypt_shared_lib_path = '/lib/mongo_crypt_v1.so'
  )

  encrypted_client, err = mdb_client(connection_string, auto_encryption)
  if err is not None:
    print(err)
    sys.exit(1)


  payload = {
    "name": {
      "firstName": "Poorna",
      "lastName": "Muggle",
      "otherNames": None,
    },
    "address": {
      "streetAddress": "29 Bson Street",
      "suburbCounty": "Mongoville",
      "stateProvince": "Victoria",
      "zipPostcode": "3999",
      "country": "Oz"
    },
    "dob": datetime(1999, 1, 12),
    "phoneNumber": "1800MONGO",
    "salary": 999999.99,
    "taxIdentifier": "78SDSSWN001",
    "role": [
      "CE"
    ]
  }

  try:

    # Retrieve the DEK UUID
    data_key_id_1 = client_encryption.get_key_by_alt_name("dataKey1")["_id"]
    if data_key_id_1 is None:
      print("Failed to find DEK")
      sys.exit()

    # Do deterministic fields
    payload["name"]["firstName"] = client_encryption.encrypt(payload["name"]["firstName"], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic, data_key_id_1)
    payload["name"]["lastName"] = client_encryption.encrypt(payload["name"]["lastName"], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic, data_key_id_1)

    # Do random fields
    if payload["name"]["otherNames"] is None:
      del(payload["name"]["otherNames"])
    else:
      payload["name"]["otherNames"] = client_encryption.encrypt(payload["name"]["otherNames"], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, data_key_id_1)
    payload["address"] = client_encryption.encrypt(payload["address"], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, data_key_id_1)
    payload["dob"] = client_encryption.encrypt(payload["dob"], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, data_key_id_1)
    payload["phoneNumber"] = client_encryption.encrypt(payload["phoneNumber"], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, data_key_id_1)
    payload["salary"] = client_encryption.encrypt(payload["salary"], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, data_key_id_1)
    payload["taxIdentifier"] = client_encryption.encrypt(payload["taxIdentifier"], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, data_key_id_1)

    # Test if the data is encrypted
    for data in [ payload["name"]["firstName"], payload["name"]["lastName"], payload["address"], payload["dob"], payload["phoneNumber"], payload["salary"], payload["taxIdentifier"]]:
      if type(data) is not Binary or data.subtype != 6:
        print("Data is not encrypted")
        sys.exit()

    result = client[encrypted_db_name][encrypted_coll_name].insert_one(payload)

    print(result.inserted_id)

    # Encrypted data to query 
    encrypted_name =  client_encryption.encrypt("Poorna", Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic, data_key_id_1)

  except EncryptionError as e:
    print(f"Encryption error: {e}")
    sys.exit()

  # WRITE YOUR QUERY HERE FOR AUTODECRYPTION. REMEMBER WHICH CLIENT TO USE!
  try:
    encrypted_doc = 

    print(encrypted_doc)
  except EncryptionError as e:
    print(f"Encryption error: {e}")
    sys.exit()



if __name__ == "__main__":
  main()