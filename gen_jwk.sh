python -c "
import json
from jwcrypto import jwk

key = jwk.JWK.from_pem(open('private_key.pem', 'rb').read())
pubkey_json = key.export_public()
pubkey_dict = json.loads(pubkey_json)
pubkey = jwk.JWK()
pubkey.import_key(**pubkey_dict)
print(pubkey.export())
" > client_jwk.json
