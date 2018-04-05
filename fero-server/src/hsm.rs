use failure::Error;
use libyubihsm::*;
use num::BigUint;
use pretty_good::*;
use yasna;

#[derive(Clone, Debug)]
pub struct HsmSigner {
    yubihsm: Yubihsm,
    connector: Connector,
    session: Session,
}

impl HsmSigner {
    pub fn new(connector_url: &str, authkey: u16, password: &str) -> Result<HsmSigner, Error> {
        let yubihsm = Yubihsm::new()?;
        let connector = yubihsm.connector().connect(connector_url)?;
        let session = connector.create_session_from_password(authkey, password, true)?;

        Ok(HsmSigner { yubihsm, connector, session })
    }

    fn create_digestinfo(payload: &[u8], hash_algo: HashAlgorithm) -> Result<Vec<u8>, Error> {
        let oid = hash_algo.asn1_oid()?;

        Ok(yasna::construct_der(|writer| {
            writer.write_sequence(|seq_writer| {
                seq_writer.next().write_sequence(|oid_seq_writer| {
                    oid_seq_writer.next().write_oid(&oid);
                    oid_seq_writer.next().write_null();
                });
                seq_writer.next().write_bytes(payload);
            });
        }))
    }

    pub fn create_signature<T: AsRef<[u8]>>(
        &self,
        payload: T,
        signing_key: u16,
        hash_algorithm: HashAlgorithm,
    ) -> Result<SignaturePacket, Error> {
        let mut sig_packet = SignaturePacket::new(
            SignatureType::BinaryDocument,
            PublicKeyAlgorithm::Rsa,
            hash_algorithm,
        )?;

        let signable_payload = sig_packet.signable_payload(payload)?;
        let digestinfo = HsmSigner::create_digestinfo(&signable_payload, hash_algorithm)?;

        let signature = self.session.sign_pkcs1v1_5(signing_key, false, digestinfo)?;
        sig_packet.set_contents(Signature::Rsa(BigUint::from_bytes_be(&signature)))?;

        Ok(sig_packet)
    }
}
