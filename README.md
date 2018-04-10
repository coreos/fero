# fero

fero is a secure signing server built around the [YubiHSM2]. fero maintains a
set of private RSA keys in the YubiHSM and uses them to produce PGP (or
PKCS#1v1.5) signatures when an authorized signing request is received. It is
designed to be a replacement for manual signing processes with `gpg` or `openssl
rsautl -sign`.

[YubiHSM2]: https://www.yubico.com/products/yubihsm/

## Model
fero makes a distinction between private keys it manages (called "secrets") and
public keys which can be used to manage and use secrets (called "users"). Each
secret has its own numerical threshold for performing signing or management
operations, and each user has a weight for each individual secret. Thus, signing
permissions can be controlled highly granularly - each user is explicitly
granted fractional control over any secrets they may have access to. This level
of granularity can also be used to build a signing hierarchy - a project with
artifacts produced by several different teams but signed by a single secret can
assign weights for the top-level secret only to team-level secrets which are
also stored in fero. Individual team members are then assigned weight for their
team's secret only, and when all teams have individually signed an artifact, the
top-level secret can then be used to re-sign the artifact.

Signing and online management operations with fero all follow the same basic
workflow:
* The payload is generated.
    * For signing operations, this is the actual artifact to sign.
    * For management operations, this is a specially formatted payload generated
      with the fero command-line client.
* Each user who wishes to authorize the operation signs the payload with their
  public key.
* The user signatures are collected and submitted by a single party along with
  the actual request to perform the operation.
* The fero server verifies each submitted user signature, and sums their weights
  for the requested secret.
* If the secret's threshold is met or exceeded, the fero server performs the
  operation and returns any artifact produced by the operation.
    * For signing operations, this is the signature by the secret over the
      payload.
    * For management operations, there is no artifact produced.

## Deployment

### Structure and requirements
fero is intended to be deployed on a machine which is not directly connected to
the Internet. To that end, there are three components to fero:
* The fero server. This is run on a non-Internet-connected machine with the
  YubiHSM2 present.
* The fero bastion. This is run on a machine with limited network access that
  must also have access to the non-Internet-connected server machine. It acts as
  a simple proxy between clients and the server.
* The fero client. This is run by fero users on any machine with access to the
  fero bastion.

The fero server requires a system with `libyubihsm.so` from the [YubiHSM2 SDK]
installed, and a YubiHSM2 device attached to the system.

[YubiHSM2 SDK]: https://developers.yubico.com/YubiHSM2/Releases/

### Setup
Both of these methods assume you are starting with a YubiHSM2 in the
factory-default configuration. If not, you should reset your YubiHSM2.

#### Containerized setup (recommended)
On the `fero-server` host:
1. Preload the fero-server and yubihsm-connector Docker images onto the host.
   These can be built from `fero-server/Dockerfile` and
   `fero-server/Dockerfile.connector`, respectively.
2. Configure a Docker bridge network over which the connector and server can
   communicate:
```sh
docker network create --driver bridge fero
```
3. Create a container for the connector:
```sh
docker create --name yubihsm-connector --network fero -v /dev:/dev --privileged=true yubihsm-connector
docker start yubihsm-connector
```
4. Provision the YubiHSM2 via fero-server's `provision` command:
```sh
docker run -it --rm --network fero -v ${FERO_DATA_PATH}:/fero fero-server provision -y
```
You will be prompted for two passwords, one for the new administrative AuthKey
that will be created on the YubiHSM2 and one for the application AuthKey that
fero-server will use.

5. Create and run the fero-server container:
```sh
docker create --name fero-server --network fero -v ${FERO_DATA_PATH}:/fero -t fero-server serve -k 3 -w $YOUR_APP_PASSWORD
docker start fero-server
```
6. Add secrets and users as desired (see "Management" section).

On the `fero-bastion` host:
1. Preload the fero-bastion Docker image onto the host. This can be built from
   `fero-bastion/Dockerfile`.
2. Create and run the fero-bastion container:
```sh
docker create --name fero-bastion -t fero-bastion --server-address $FERO_SERVER_ADDRESS
docker start fero-bastion
```

#### Non-containerized setup
On the `fero-server` host: 
1. Configure [`yubihsm-connector`]. Make a note of its settings, as you'll need
   to tell `fero-server` about them.
2. If you haven't already configured your YubiHSM2, do so now with `fero-server -d /path/to/fero.db
   provision -y`. Make a note of both passwords you enter here; you'll need the administrative
   AuthKey if you ever need to reconfigure the YubiHSM2, and you'll need the application AuthKey to
   use fero.
4. Start `fero-server` with the options you've noted from the previous steps,
   and the desired address/port to listen on: `fero-server -d /path/to/fero.db serve -a
   ${LISTEN_ADDR} -k 3 -w ${APPLICATION_PASSWORD} -c ${CONNECTOR_URL} -p ${LISTEN_PORT}`

On the `fero-bastion` host:

1. Run `fero-bastion -a ${BASTION_LISTEN_ADDRESS} -p ${BASTION_LISTEN_PORT} -s
   ${SERVER_LISTEN_ADDRESS} -r ${SERVER_LISTEN_PORT}`.

[`yubihsm-connector`]: https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/
[`yubihsm-shell`]: https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-shell/

### Management
The examples given are for use with the containerized setup listed above. If
you're not using the containerized setup, just drop the Docker portions of the
examples and run `fero-server` directly. You will also need to provide the
connector URL and database path.

#### Secrets 
Fero supports both PGP and raw RSA private keys. Secrets can be added with
either `add-pgp-secret` or `add-pem-secret`, depending on the type of secret you
wish to add. Each also requires the AuthKey and database path. For PGP secrets,
you will also need to specify which subkey you wish to store.

**Important**: Fero does not support ASCII-armored PGP data, so if your private
key is ASCII-armored you will need to dearmor it (`gpg2 --dearmor
armored_key.gpg > dearmored_key.gpg`).

* PEM secrets:
```sh
docker run -it --rm --network fero \
    -v ${FERO_DATA_PATH}:/fero -v $(pwd):/data fero-server add-pem-secret \
    -k 3 -w $YOUR_APP_PASSWORD \
    --name $SECRET_NAME \
    --threshold $SECRET_THRESHOLD \
    --file path/to/some.pem
```
* PGP secrets:
```sh
docker run -it --rm --network fero \
    -v ${FERO_DATA_PATH}:/fero -v $(pwd):/data fero-server add-pgp-secret \
    -k 3 -w $YOUR_APP_PASSWORD \
    --name $SECRET_NAME \
    --threshold $SECRET_THRESHOLD \
    --subkey $DESIRED_SUBKEY \
    --file path/to/some_private_key.pgp
```

#### Users
Adding users can be done with the `add-user` subcommand. 

**Important**: Fero does not support ASCII-armored PGP data, so if your public
key is ASCII-armored you will need to dearmor it (`gpg2 --dearmor
armored_key.gpg > dearmored_key.gpg`).
```sh
docker run -it --rm --network fero \
    -v ${FERO_DATA_PATH}:/fero -v $(pwd):/data fero-server add-user \
    -k 3 -w $YOUR_APP_PASSWORD \
    --file path/to/some_public_key.pgp
```

Setting a user's weight for a key can be done with the `set-user-weight`
subcommand:
```sh
docker run -it --rm --network fero \
    -v ${FERO_DATA_PATH}:/fero fero-server set-user-weight \
    --name $SECRET_NAME
    --user $USER_PGP_FINGERPRINT \
    --weight $NEW_WEIGHT
```

## Usage

### Signing
Once you've populated the server with your secrets and users, and set the
appropriate weights and thresholds, signing is relatively straightforward.
Simply use the `sign` subcommand of `fero-client` along with each user's
signature:
```sh
fero-client -a $BASTION_ADDRESS sign \
    -f myfile.txt \
    -o myfile.txt.sig \
    -k mysecret \
    -s myfile.txt.sig.1 -s myfile.txt.sig.2 -s myfile.txt.sig.3
```

For PKCS signatures, there's a little more work to do. Fero expects the "file"
for PKCS signatures to be the actual SHA256 hash of the content you're signing:
```sh
openssl dgst -sha256 -out myfile.txt.hash myfile.txt
# Sign myfile.txt.hash as normal
fero-client -a $BASTION_ADDRESS sign \
    -f myfile.txt.hash \
    -o myfile.txt.sig \
    -k mysecret \
    -s myfile.txt.sig.1 -s myfile.txt.sig.2 -s myfile.txt.sig.3
```

### User/secret management
Key management operations use the same authentication method as signing
operations, so any set of users which can sign with a given key can also manage
it. `fero-client` includes subcommands for generating the appropriate payloads
to sign for the various key management operations.

#### Setting secret thresholds
```sh
fero-client -a $BASTION_ADDRESS threshold-payload -f threshold_payload -k mysecret -t 1000
# Sign threshold_payload
fero-client -a $BASTION_ADDRESS threshold -k mysecret -t 1000 \
    -s threshold_payload.sig.1 -s threshold_payload.sig.2 -s threshold_payload.sig.3
```

#### Updating users' weights
```sh
fero-client -a $BASTION_ADDRESS weight-payload -f weight_payload -k mysecret -u $USERID -w 300
# Sign weight_payload
fero-client -a $BASTION_ADDRESS weight -k mysecret -u $USERID -w 300 \
    -s weight_payload.sig.1 -s weight_payload.sig.2 -s weight_payload.sig.3
```
