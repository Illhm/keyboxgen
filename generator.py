import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
import xml.etree.ElementTree as ET
from xml.dom import minidom
import random
import string
import uuid
from pyasn1.type import univ, namedtype, tag, namedval, constraint
from pyasn1.codec.der import encoder

# === ASN.1 Definition for Android Key Attestation ===
# Based on https://source.android.com/security/keystore/attestation

class SecurityLevel(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('Software', 0),
        ('TrustedEnvironment', 1),
        ('StrongBox', 2)
    )

class VerifiedBootState(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('Verified', 0),
        ('SelfSigned', 1),
        ('Unverified', 2),
        ('Failed', 3)
    )

class RootOfTrust(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('verifiedBootKey', univ.OctetString()),
        namedtype.NamedType('deviceLocked', univ.Boolean()),
        namedtype.NamedType('verifiedBootState', VerifiedBootState()),
        namedtype.NamedType('verifiedBootHash', univ.OctetString())
    )
    tagSet = univ.Sequence.tagSet.tagExplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 704))

# Helper types with Explicit Tags
class PurposeSet(univ.SetOf):
    componentType = univ.Integer()
    tagSet = univ.SetOf.tagSet.tagExplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))

class Algorithm(univ.Integer):
    tagSet = univ.Integer.tagSet.tagExplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))

class KeySize(univ.Integer):
    tagSet = univ.Integer.tagSet.tagExplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))

class DigestSet(univ.SetOf):
    componentType = univ.Integer()
    tagSet = univ.SetOf.tagSet.tagExplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 5))

class EcCurve(univ.Integer):
    tagSet = univ.Integer.tagSet.tagExplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10))

class OsVersion(univ.Integer):
    tagSet = univ.Integer.tagSet.tagExplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 705))

class OsPatchLevel(univ.Integer):
    tagSet = univ.Integer.tagSet.tagExplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 706))

class AuthorizationList(univ.Sequence):
    # Defining a subset of tags commonly found in TEE keys
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('purpose', PurposeSet()),
        namedtype.OptionalNamedType('algorithm', Algorithm()),
        namedtype.OptionalNamedType('keySize', KeySize()),
        namedtype.OptionalNamedType('digest', DigestSet()),
        namedtype.OptionalNamedType('ecCurve', EcCurve()),
        namedtype.OptionalNamedType('rootOfTrust', RootOfTrust()),
        namedtype.OptionalNamedType('osVersion', OsVersion()),
        namedtype.OptionalNamedType('osPatchLevel', OsPatchLevel())
    )

class KeyDescription(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('attestationVersion', univ.Integer()),
        namedtype.NamedType('attestationSecurityLevel', SecurityLevel()),
        namedtype.NamedType('keymasterVersion', univ.Integer()),
        namedtype.NamedType('keymasterSecurityLevel', SecurityLevel()),
        namedtype.NamedType('attestationChallenge', univ.OctetString()),
        namedtype.NamedType('uniqueId', univ.OctetString()),
        namedtype.NamedType('softwareEnforced', AuthorizationList()),
        namedtype.NamedType('teeEnforced', AuthorizationList())
    )

# ====================================================

def generate_ec_key_pair():
    # SECP256R1 is standard for Android Keybox
    return ec.generate_private_key(ec.SECP256R1())

def generate_rsa_key_pair():
    # RSA 2048 is standard for Google Root
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

def random_string(length=8):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def random_hex(length=16):
    return ''.join(random.choices("0123456789abcdef", k=length))

def generate_attestation_extension(challenge=b'123456'):
    # Create the structure
    key_desc = KeyDescription()
    key_desc.setComponentByName('attestationVersion', 300) # Attestation v3 (Android 12)
    key_desc.setComponentByName('attestationSecurityLevel', 'StrongBox')
    key_desc.setComponentByName('keymasterVersion', 300) # KM v3
    key_desc.setComponentByName('keymasterSecurityLevel', 'StrongBox')
    key_desc.setComponentByName('attestationChallenge', challenge)
    key_desc.setComponentByName('uniqueId', b'')

    # softwareEnforced (Usually empty for TEE keys, or minimal)
    sw_list = AuthorizationList()
    key_desc.setComponentByName('softwareEnforced', sw_list)

    # teeEnforced
    # Populate with realistic values for EC P-256
    tee_list = AuthorizationList()

    # Purpose: SIGN(2), VERIFY(3)
    purposes = PurposeSet()
    purposes.setComponentByPosition(0, univ.Integer(2))
    purposes.setComponentByPosition(1, univ.Integer(3))
    tee_list.setComponentByName('purpose', purposes)

    # Algorithm: EC(3)
    tee_list.setComponentByName('algorithm', Algorithm(3))

    # KeySize: 256
    tee_list.setComponentByName('keySize', KeySize(256))

    # Digest: SHA-2-256(4)
    digests = DigestSet()
    digests.setComponentByPosition(0, univ.Integer(4))
    tee_list.setComponentByName('digest', digests)

    # EcCurve: P-256(1)
    tee_list.setComponentByName('ecCurve', EcCurve(1))

    # Root Of Trust
    rot = RootOfTrust()
    rot.setComponentByName('verifiedBootKey', b'\x00'*32) # Dummy key
    rot.setComponentByName('deviceLocked', True)
    rot.setComponentByName('verifiedBootState', 'Verified')
    rot.setComponentByName('verifiedBootHash', b'\x00'*32) # Dummy hash
    tee_list.setComponentByName('rootOfTrust', rot)

    # OS Version: 12.0.0 -> 120000
    tee_list.setComponentByName('osVersion', OsVersion(120000))

    # OS Patch Level: YYYYMM -> 202502
    tee_list.setComponentByName('osPatchLevel', OsPatchLevel(202502))

    key_desc.setComponentByName('teeEnforced', tee_list)

    return encoder.encode(key_desc)

def cert_to_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

def key_to_pem(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

def main():
    print("Generating Fresh & Strong Keybox...")

    device_id = random_string(16)
    print(f"Device ID: {device_id}")

    # ==========================================
    # 1. Root CA (RSA 2048)
    # Subject/Issuer: serialNumber=<hex>
    # ==========================================
    root_key = generate_rsa_key_pair()
    # Use the known Google Hardware Attestation Root Serial Number to mimic it
    root_serial_dn = "f92009e853b6b045"

    # Note: Attributes must be in specific order? PyCa handles it.
    root_name = x509.Name([
        x509.NameAttribute(NameOID.SERIAL_NUMBER, root_serial_dn),
    ])

    root_builder = x509.CertificateBuilder()
    root_builder = root_builder.subject_name(root_name)
    root_builder = root_builder.issuer_name(root_name) # Self-signed

    now = datetime.datetime.now(datetime.timezone.utc)
    # Valid for 20 years for root
    root_builder = root_builder.not_valid_before(now - datetime.timedelta(hours=1))
    root_builder = root_builder.not_valid_after(now + datetime.timedelta(days=365 * 20))
    root_builder = root_builder.serial_number(x509.random_serial_number())
    root_builder = root_builder.public_key(root_key.public_key())

    # CA: TRUE
    root_builder = root_builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    # Key Usage: KeyCertSign, CRLSign
    root_builder = root_builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ), critical=True
    )

    # Self-sign with RSA
    root_cert = root_builder.sign(private_key=root_key, algorithm=hashes.SHA256())

    # ==========================================
    # 2. Intermediate CA (ECDSA P-256)
    # Subject: title=TEE, serialNumber=<hex>
    # Issuer: Root Subject
    # ==========================================
    intermediate_key = generate_ec_key_pair()
    inter_serial_dn = random_hex(32) # Inter often has longer serial? Valid report says 32 chars (16 bytes hex)

    inter_name = x509.Name([
        x509.NameAttribute(NameOID.TITLE, u"TEE"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, inter_serial_dn),
    ])

    inter_builder = x509.CertificateBuilder()
    inter_builder = inter_builder.subject_name(inter_name)
    inter_builder = inter_builder.issuer_name(root_cert.subject)

    # Valid for 10 years
    inter_builder = inter_builder.not_valid_before(now - datetime.timedelta(hours=1))
    inter_builder = inter_builder.not_valid_after(now + datetime.timedelta(days=365 * 10))
    inter_builder = inter_builder.serial_number(x509.random_serial_number())
    inter_builder = inter_builder.public_key(intermediate_key.public_key())

    # CA: TRUE
    inter_builder = inter_builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    # Key Usage: KeyCertSign, CRLSign
    inter_builder = inter_builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ), critical=True
    )

    # Signed by Root (RSA)
    inter_cert = inter_builder.sign(private_key=root_key, algorithm=hashes.SHA256())

    # ==========================================
    # 3. Leaf Certificate (ECDSA P-256)
    # Subject: title=TEE, serialNumber=<hex>
    # Issuer: Intermediate Subject
    # ==========================================
    device_key = generate_ec_key_pair()
    leaf_serial_dn = random_hex(32)

    leaf_name = x509.Name([
        x509.NameAttribute(NameOID.TITLE, u"TEE"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, leaf_serial_dn),
    ])

    leaf_builder = x509.CertificateBuilder()
    leaf_builder = leaf_builder.subject_name(leaf_name)
    leaf_builder = leaf_builder.issuer_name(inter_cert.subject)

    # Valid for 10 years
    leaf_builder = leaf_builder.not_valid_before(now - datetime.timedelta(hours=1))
    leaf_builder = leaf_builder.not_valid_after(now + datetime.timedelta(days=365 * 10))
    leaf_builder = leaf_builder.serial_number(x509.random_serial_number())
    leaf_builder = leaf_builder.public_key(device_key.public_key())

    # CA: FALSE
    leaf_builder = leaf_builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    # Key Usage: DigitalSignature...
    leaf_builder = leaf_builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False, # For EC
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ), critical=True
    )

    # Add Android Key Attestation Extension
    attestation_oid = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
    attestation_data = generate_attestation_extension()

    leaf_builder = leaf_builder.add_extension(
        x509.UnrecognizedExtension(attestation_oid, attestation_data),
        critical=False
    )

    # Signed by Intermediate (ECDSA)
    leaf_cert = leaf_builder.sign(private_key=intermediate_key, algorithm=hashes.SHA256())

    # Construct XML
    root = ET.Element("AndroidAttestation")
    ET.SubElement(root, "NumberOfKeyboxes").text = "1"

    keybox = ET.SubElement(root, "Keybox", DeviceID=device_id)

    key_el = ET.SubElement(keybox, "Key", algorithm="ecdsa")

    private_key_el = ET.SubElement(key_el, "PrivateKey", format="pem")
    private_key_el.text = "\n" + key_to_pem(device_key).strip() + "\n"

    cert_chain_el = ET.SubElement(key_el, "CertificateChain")
    ET.SubElement(cert_chain_el, "NumberOfCertificates").text = "3"

    # Order: Leaf -> Intermediate -> Root
    certs = [leaf_cert, inter_cert, root_cert]

    for cert in certs:
        cert_el = ET.SubElement(cert_chain_el, "Certificate", format="pem")
        cert_el.text = "\n" + cert_to_pem(cert).strip() + "\n"

    xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="   ")

    filename = "generated_keybox.xml"
    with open(filename, "w") as f:
        f.write(xml_str)

    print(f"Generated {filename}")

if __name__ == "__main__":
    main()
