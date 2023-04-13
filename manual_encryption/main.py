from bson.binary import STANDARD, Binary
from bson.codec_options import CodecOptions
from datetime import datetime
from pymongo import MongoClient
from pymongo.encryption import Algorithm
from pymongo.encryption import ClientEncryption
from pymongo.errors import EncryptionError, ServerSelectionTimeoutError, ConnectionFailure
from urllib.parse import quote_plus
import sys


# IN VALUES HERE!
PETNAME = "poetic-hound"
MDB_PASSWORD = "password123"
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

  payload = {
    "name": {
      "firstName": "Manish",
      "lastName": "Engineer",
      "otherNames": None,
    },
    "address": {
      "streetAddress": "1 Bson Street",
      "suburbCounty": "Mongoville",
      "stateProvince": "Victoria",
      "zipPostcode": "3999",
      "country": "Oz"
    },
    "dob": datetime(1980, 10, 10),
    "phoneNumber": "1800MONGO",
    "salary": 999999.99,
    "taxIdentifier": "78SD20NN001",
    "role": [
      "CTO"
    ]
  }

  try:

    # retrieve the DEK UUID
    data_key_id_1 = client_encryption.get_key_by_alt_name("dataKey1")["_id"]# Put code here to find the _id of the DEK we created previously
    if data_key_id_1 is None:
      print("Failed to find DEK")
      sys.exit()

    # WRITE CODE HERE TO ENCRYPT THE APPROPRIATE FIELDS
    # Don't forget to handle to event of name.otherNames being null
    first_name_raw = payload["name"]["firstName"]
    last_name_raw = payload["name"]["lastName"]
    option_det = Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic
    encrypted_first_name = client_encryption.encrypt(first_name_raw, option_det, data_key_id_1)
    encrypted_last_name = client_encryption.encrypt(last_name_raw, option_det, data_key_id_1)
    # Do deterministic fields
    payload["name"]["firstName"] = encrypted_first_name
    payload["name"]["lastName"] = encrypted_last_name

    option_ran = Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random
    # Do random fields
    if payload["name"]["otherNames"] is None:
      # put code here to delete this field if None
      del payload["name"]["otherNames"]
    else:
      payload["name"]["otherNames"] = client_encryption.encrypt(payload["name"]["otherNames"], option_ran, data_key_id_1)# Put code here to encrypt the data
      #for k in payload["address"]:
      #    payload["address"][k] = client_encryption.encrypt(payload["address"][k], option_ran, data_key_id_1)      
    payload["address"] = client_encryption.encrypt(payload["address"], option_ran, data_key_id_1)# Put code here to encrypt the data
    payload["dob"] = client_encryption.encrypt(payload["dob"], option_ran, data_key_id_1)# Put code here to encrypt the data
    payload["phoneNumber"] = client_encryption.encrypt(payload["phoneNumber"], option_ran, data_key_id_1)# Put code here to encrypt the data
    payload["salary"] = client_encryption.encrypt(payload["salary"], option_ran, data_key_id_1)# Put code here to encrypt the data
    payload["taxIdentifier"] = client_encryption.encrypt(payload["taxIdentifier"], option_ran, data_key_id_1)# Put code here to encrypt the data


    # Test if the data is encrypted
    for data in [ payload["name"]["firstName"], payload["name"]["lastName"], payload["address"], payload["dob"], payload["phoneNumber"], payload["salary"], payload["taxIdentifier"]]:
      if type(data) is not Binary and data.subtype != 6:
        print("Data is not encrypted", data)
        sys.exit(-1)

    if "otherNames" in payload["name"] and payload["name"]["otherNames"] is None:
      print("None cannot be encrypted")
      sys.exit(-1)

  except EncryptionError as e:
    print(f"Encryption error: {e}")


  print(payload)

  result = client[encrypted_db_name][encrypted_coll_name].insert_one(payload)

  print(result.inserted_id)

if __name__ == "__main__":
  main()
