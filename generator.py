import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import xml.etree.ElementTree as ET
from xml.dom import minidom
import random
import string
import uuid
from pyasn1.type import univ, namedtype, tag, namedval
from pyasn1.codec.der import encoder

# === ASN.1 Definition for Android Key Attestation ===
# Based on https://source.android.com/security/keystore/attestation

class SecurityLevel(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('Software', 0),
        ('TrustedEnvironment', 1),
        ('StrongBox', 2)
    )

class AuthorizationList(univ.Sequence):
    # AuthorizationList is a SEQUENCE of optional explicitly tagged fields.
    # For a minimal valid structure, an empty sequence is acceptable as all fields are optional.
    pass

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

def generate_key_pair():
    # SECP256R1 is standard for Android Keybox
    return ec.generate_private_key(ec.SECP256R1())

def random_string(length=8):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def generate_attestation_extension(challenge=b'123456'):
    # Create the structure
    key_desc = KeyDescription()
    key_desc.setComponentByName('attestationVersion', 4) # Attestation v4 (Android 10/11)
    key_desc.setComponentByName('attestationSecurityLevel', 'TrustedEnvironment')
    key_desc.setComponentByName('keymasterVersion', 4) # KM v4
    key_desc.setComponentByName('keymasterSecurityLevel', 'TrustedEnvironment')
    key_desc.setComponentByName('attestationChallenge', challenge)
    key_desc.setComponentByName('uniqueId', b'') # Empty for most cases

    # Authorization Lists
    # For a realistic look, we should populate "teeEnforced" with some tags.
    # Tag 702 (purpose) = [2] (SIGN, VERIFY) -> Tag [702] EXPLICIT SET OF INTEGER
    # But defining the full schema is huge.
    # Empty sequences are valid for "everything optional".

    # softwareEnforced
    sw_list = AuthorizationList()
    key_desc.setComponentByName('softwareEnforced', sw_list)

    # teeEnforced
    tee_list = AuthorizationList()
    key_desc.setComponentByName('teeEnforced', tee_list)

    return encoder.encode(key_desc)

def create_certificate(subject_cn, issuer_cn, public_key, signing_key, serial_number=None, ca=False):
    # This helper is for CA certs mostly. For Leaf, we use specific logic in main.
    if serial_number is None:
        serial_number = x509.random_serial_number()

    org_name = f"Android OEM {random_string(4)}"

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    ])

    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name if subject_cn == issuer_cn else u"Android Root CA"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    ])

    if subject_cn == issuer_cn:
        issuer = subject

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = builder.not_valid_before(now - datetime.timedelta(hours=1))
    builder = builder.not_valid_after(now + datetime.timedelta(days=365 * 10))

    builder = builder.serial_number(serial_number)
    builder = builder.public_key(public_key)

    builder = builder.add_extension(
        x509.BasicConstraints(ca=ca, path_length=None), critical=True,
    )

    certificate = builder.sign(
        private_key=signing_key, algorithm=hashes.SHA256(),
    )
    return certificate, subject

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

    # 1. Root CA
    root_key = generate_key_pair()
    # Using more official-looking names
    root_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Google Hardware Attestation Root"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Google Inc"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    ])
    root_builder = x509.CertificateBuilder()
    root_builder = root_builder.subject_name(root_name)
    root_builder = root_builder.issuer_name(root_name)
    root_builder = root_builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    root_builder = root_builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
    root_builder = root_builder.serial_number(x509.random_serial_number())
    root_builder = root_builder.public_key(root_key.public_key())
    root_builder = root_builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    root_cert = root_builder.sign(private_key=root_key, algorithm=hashes.SHA256())

    # 2. Intermediate CA
    intermediate_key = generate_key_pair()
    inter_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Google Hardware Attestation Intermediate"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Google Inc"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    ])
    inter_builder = x509.CertificateBuilder()
    inter_builder = inter_builder.subject_name(inter_name)
    inter_builder = inter_builder.issuer_name(root_cert.subject)
    inter_builder = inter_builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    inter_builder = inter_builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
    inter_builder = inter_builder.serial_number(x509.random_serial_number())
    inter_builder = inter_builder.public_key(intermediate_key.public_key())
    inter_builder = inter_builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    inter_cert = inter_builder.sign(private_key=root_key, algorithm=hashes.SHA256())

    # 3. Leaf Certificate (Device)
    device_key = generate_key_pair()
    leaf_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Android Keystore Key"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Google Inc"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        # TEE title often used
    ])

    leaf_builder = x509.CertificateBuilder()
    leaf_builder = leaf_builder.subject_name(leaf_name)
    leaf_builder = leaf_builder.issuer_name(inter_cert.subject)
    leaf_builder = leaf_builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    leaf_builder = leaf_builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
    leaf_builder = leaf_builder.serial_number(x509.random_serial_number())
    leaf_builder = leaf_builder.public_key(device_key.public_key())
    leaf_builder = leaf_builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

    # Add Android Key Attestation Extension
    attestation_oid = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
    attestation_data = generate_attestation_extension()

    # The cryptography library requires us to wrap custom extensions in UnrecognizedExtension
    # if we don't have a specific class for it registered.
    leaf_builder = leaf_builder.add_extension(
        x509.UnrecognizedExtension(attestation_oid, attestation_data),
        critical=False
    )

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
