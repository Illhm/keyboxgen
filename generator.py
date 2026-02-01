import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import xml.etree.ElementTree as ET
from xml.dom import minidom
import random

def generate_key_pair():
    return ec.generate_private_key(ec.SECP256R1())

def create_certificate(subject_name, issuer_name, public_key, signing_key, serial_number=None, ca=False):
    if serial_number is None:
        serial_number = x509.random_serial_number()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test Org"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test Org"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    ]))
    builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
    builder = builder.serial_number(serial_number)
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=ca, path_length=None), critical=True,
    )
    certificate = builder.sign(
        private_key=signing_key, algorithm=hashes.SHA256(),
    )
    return certificate

def cert_to_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

def key_to_pem(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

def main():
    print("Generating Keybox...")

    # 1. Root CA
    root_key = generate_key_pair()
    root_cert = create_certificate(u"Root CA", u"Root CA", root_key.public_key(), root_key, ca=True)

    # 2. Intermediate CA
    intermediate_key = generate_key_pair()
    intermediate_cert = create_certificate(u"Intermediate CA", u"Root CA", intermediate_key.public_key(), root_key, ca=True)

    # 3. Leaf Certificate (The Device Key)
    device_key = generate_key_pair()
    device_cert = create_certificate(u"Device Key", u"Intermediate CA", device_key.public_key(), intermediate_key, ca=False)

    # Construct XML
    root = ET.Element("AndroidAttestation")
    ET.SubElement(root, "NumberOfKeyboxes").text = "1"

    keybox = ET.SubElement(root, "Keybox", DeviceID="generated_device")

    key_el = ET.SubElement(keybox, "Key", algorithm="ecdsa")

    private_key_el = ET.SubElement(key_el, "PrivateKey", format="pem")
    private_key_el.text = "\n" + key_to_pem(device_key).strip() + "\n"

    cert_chain_el = ET.SubElement(key_el, "CertificateChain")
    ET.SubElement(cert_chain_el, "NumberOfCertificates").text = "3"

    # Order: Leaf -> Intermediate -> Root
    certs = [device_cert, intermediate_cert, root_cert]

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
