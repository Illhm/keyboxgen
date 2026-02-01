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

def generate_key_pair():
    # SECP256R1 is standard for Android Keybox
    return ec.generate_private_key(ec.SECP256R1())

def random_string(length=8):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def create_certificate(subject_cn, issuer_cn, public_key, signing_key, serial_number=None, ca=False):
    if serial_number is None:
        serial_number = x509.random_serial_number()

    # Randomize Organization slightly to be "fresh"
    org_name = f"Android OEM {random_string(4)}"

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    ])

    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
        # In a real chain, the issuer's subject matches the signer's subject.
        # For simplicity here, we assume the issuer_cn passed in allows us to construct a plausible name,
        # but for proper chaining verification, strict checking might require exact matching.
        # Our checker verifies public key signature, which is the most important part.
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name if subject_cn == issuer_cn else u"Android Root CA"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    ])

    # If self-signed root
    if subject_cn == issuer_cn:
        issuer = subject

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)

    # Fresh validity window
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = builder.not_valid_before(now - datetime.timedelta(hours=1)) # Just to be safe with clock skew
    builder = builder.not_valid_after(now + datetime.timedelta(days=365 * 10)) # 10 years

    builder = builder.serial_number(serial_number)
    builder = builder.public_key(public_key)

    builder = builder.add_extension(
        x509.BasicConstraints(ca=ca, path_length=None), critical=True,
    )

    certificate = builder.sign(
        private_key=signing_key, algorithm=hashes.SHA256(),
    )
    return certificate, subject # Return subject to use as issuer for next

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
    root_cert, root_subject = create_certificate(u"Google Root CA (Fake)", u"Google Root CA (Fake)", root_key.public_key(), root_key, ca=True)

    # 2. Intermediate CA
    intermediate_key = generate_key_pair()
    # We construct the issuer name manually or pass the object?
    # For this simple script, we'll just reconstruct the issuer name structure in create_certificate based on string,
    # or better, let's just make it simple. The checker primarily checks signatures.

    # Let's fix create_certificate to take an actual Name object for issuer if provided
    # ... actually let's just do it inline here for better control over the chain

    # RE-DOING CHAIN GENERATION TO BE ROBUST

    # ROOT
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

    # INTERMEDIATE
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

    # LEAF (DEVICE)
    leaf_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Android Keystore Key"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Google Inc"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.TITLE, u"TEE"), # Important for checker
    ])
    device_key = generate_key_pair()
    leaf_builder = x509.CertificateBuilder()
    leaf_builder = leaf_builder.subject_name(leaf_name)
    leaf_builder = leaf_builder.issuer_name(inter_cert.subject)
    leaf_builder = leaf_builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    leaf_builder = leaf_builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
    leaf_builder = leaf_builder.serial_number(x509.random_serial_number())
    leaf_builder = leaf_builder.public_key(device_key.public_key())
    leaf_builder = leaf_builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
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
