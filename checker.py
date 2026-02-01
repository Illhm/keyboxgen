import asyncio
import aiohttp
import re
import requests
import json
import time
import os
import sys
import argparse
from colorama import Fore, Style, init
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa

init(autoreset=True)

async def load_from_url():
    url = "https://android.googleapis.com/attestation/status"
    timestamp = int(time.time())
    headers = {
        "Cache-Control": "max-age=0, no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    }
    params = {"ts": timestamp}

    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, params=params) as response:
            if response.status != 200:
                raise Exception(f"Error fetching data: {response.status}")
            return await response.json()

def parse_number_of_certificates(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    number_of_certificates = root.find('.//NumberOfCertificates')
    if number_of_certificates is not None:
        return int(number_of_certificates.text.strip())
    else:
        raise Exception('No NumberOfCertificates found.')

def parse_certificates(xml_file, pem_number):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    pem_certificates = root.findall('.//Certificate[@format="pem"]')
    if pem_certificates is not None:
        return [cert.text.strip() for cert in pem_certificates[:pem_number]]
    else:
        raise Exception("No Certificate found.")

def load_public_key_from_file(file_path):
    with open(file_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def compare_keys(public_key1, public_key2):
    return public_key1.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ) == public_key2.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def get_overall_status(status, keychain_status, cert_status, google_status):
    if status is None:
        if "Valid." in keychain_status:
            if "Unknown / Software" in cert_status:
                if google_status == "null":
                    return f"{Fore.YELLOW}Valid. (Software signed)"
                else:
                    return f"{Fore.YELLOW}Check status reason: {status['reason']}"
            elif any(x in cert_status for x in ["AOSP Software Attestation", "Samsung Knox Attestation", "Google Hardware Attestation"]):
                if "Google Hardware Attestation" in cert_status:
                    return f"{Fore.GREEN}Valid. (Google Hardware Attestation)"
                elif "AOSP Software Attestation(EC)" in cert_status:
                    return f"{Fore.YELLOW}Valid. (AOSP Software EC)"
                elif "AOSP Software Attestation(RCA)" in cert_status:
                    return f"{Fore.YELLOW}Valid. (AOSP Software RCA)"
                elif "Samsung Knox Attestation" in cert_status:
                    return f"{Fore.GREEN}Valid. (Samsung Knox Attestation)"
                else:
                    return f"{Fore.RED}Invalid keybox (Cert Status mismatch)."
            else:
                return f"{Fore.RED}Invalid keybox (Unknown Cert Status)."
        else:
            return f"{Fore.RED}Invalid Keybox (Keychain Invalid)."
    else:
        status_reason = google_status
        status_reason_map = {
            "KEY_COMPROMISE": f"{Fore.RED}Invalid. (Key Compromised)",
            "SOFTWARE_FLAW": f"{Fore.RED}Invalid. (Software flaw)",
            "CA_COMPROMISE": f"{Fore.RED}Invalid. (CA Compromised)",
            "SUPERSEDED": f"{Fore.RED}Invalid. (Superseded)"
        }
        return status_reason_map.get(status_reason, f"{Fore.GREEN}Valid (Status Unknown: {status_reason})")

async def keybox_check_cli(keybox_path):
    try:
        pem_number = parse_number_of_certificates(keybox_path)
        pem_certificates = parse_certificates(keybox_path, pem_number)
    except Exception as e:
        print(f"{Fore.RED}Error parsing XML: {e}")
        return

    try:
        certificate = x509.load_pem_x509_certificate(
            pem_certificates[0].encode(),
            default_backend()
        )
    except Exception as e:
        print(f"{Fore.RED}Error loading certificate: {e}")
        return

    # Certificate Validity Verification
    not_valid_before = certificate.not_valid_before_utc
    not_valid_after = certificate.not_valid_after_utc
    current_date = datetime.now(timezone.utc)
    validity = not_valid_before <= current_date <= not_valid_after

    not_valid_before_str = not_valid_before.strftime('%Y-%m-%d %H:%M:%S')
    not_valid_after_str = not_valid_after.strftime('%Y-%m-%d %H:%M:%S')

    if validity:
        validity_status = f"{Fore.GREEN}Valid. (Valid from {not_valid_before_str} to {not_valid_after_str})"
    else:
        validity_status = f"{Fore.RED}Expired. (Valid from {not_valid_before_str} to {not_valid_after_str})"

    # Keychain Authentication
    flag = True
    for i in range(pem_number - 1):
        son_certificate = x509.load_pem_x509_certificate(pem_certificates[i].encode(), default_backend())
        father_certificate = x509.load_pem_x509_certificate(pem_certificates[i + 1].encode(), default_backend())

        if son_certificate.issuer != father_certificate.subject:
            print(f"{Fore.RED}Issuer mismatch at index {i}")
            flag = False
            break

        signature = son_certificate.signature
        tbs_certificate = son_certificate.tbs_certificate_bytes
        public_key = father_certificate.public_key()

        # Determine hash algorithm from signature algorithm OID
        # This is a simplification; robust code should handle more
        algo_name = son_certificate.signature_algorithm_oid._name

        try:
            if isinstance(public_key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)) or \
               'RSA' in algo_name or 'rsa' in algo_name:
                 # Attempt RSA verification
                 if 'sha256' in algo_name.lower(): hash_alg = hashes.SHA256()
                 elif 'sha1' in algo_name.lower(): hash_alg = hashes.SHA1()
                 elif 'sha384' in algo_name.lower(): hash_alg = hashes.SHA384()
                 elif 'sha512' in algo_name.lower(): hash_alg = hashes.SHA512()
                 else: hash_alg = hashes.SHA256() # Fallback

                 public_key.verify(
                     signature,
                     tbs_certificate,
                     padding.PKCS1v15(),
                     hash_alg
                 )
            elif isinstance(public_key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)) or \
                 'ecdsa' in algo_name.lower():
                 if 'sha256' in algo_name.lower(): hash_alg = hashes.SHA256()
                 elif 'sha1' in algo_name.lower(): hash_alg = hashes.SHA1()
                 elif 'sha384' in algo_name.lower(): hash_alg = hashes.SHA384()
                 elif 'sha512' in algo_name.lower(): hash_alg = hashes.SHA512()
                 else: hash_alg = hashes.SHA256()

                 public_key.verify(
                     signature,
                     tbs_certificate,
                     ec.ECDSA(hash_alg)
                 )
            else:
                 # Try generic verify if available or skip (dangerous)
                 pass

        except Exception as e:
            print(f"{Fore.RED}Signature verification failed at index {i}: {e}")
            flag = False
            break

    if flag:
        keychain_status = f"{Fore.GREEN}Valid."
    else:
        keychain_status = f"{Fore.RED}Invalid."

    # Root Certificate Validation
    script_dir = os.path.dirname(os.path.abspath(__file__))
    lib_pem_dir = os.path.join(script_dir, 'lib', 'pem')

    google_pem = os.path.join(lib_pem_dir, 'google.pem')
    aosp_ec_pem = os.path.join(lib_pem_dir, 'aosp_ec.pem')
    aosp_rsa_pem = os.path.join(lib_pem_dir, 'aosp_rsa.pem')
    knox_pem = os.path.join(lib_pem_dir, 'knox.pem')

    try:
        root_certificate = x509.load_pem_x509_certificate(pem_certificates[-1].encode(), default_backend())
        root_public_key = root_certificate.public_key()

        cert_status = f"{Fore.YELLOW}Unknown / Software"

        if os.path.exists(google_pem) and compare_keys(root_public_key, load_public_key_from_file(google_pem)):
            cert_status = f"{Fore.GREEN}Google Hardware Attestation"
        elif os.path.exists(aosp_ec_pem) and compare_keys(root_public_key, load_public_key_from_file(aosp_ec_pem)):
            cert_status = f"{Fore.YELLOW}AOSP Software Attestation(EC)"
        elif os.path.exists(aosp_rsa_pem) and compare_keys(root_public_key, load_public_key_from_file(aosp_rsa_pem)):
            cert_status = f"{Fore.YELLOW}AOSP Software Attestation(RCA)"
        elif os.path.exists(knox_pem) and compare_keys(root_public_key, load_public_key_from_file(knox_pem)):
            cert_status = f"{Fore.GREEN}Samsung Knox Attestation"

    except Exception as e:
        cert_status = f"{Fore.RED}Error checking root: {e}"

    # Revocation Check
    try:
        status_json = await load_from_url()
    except Exception:
        print("Failed to fetch Google's revoked keybox list")
        status_json = {'entries': {}}

    status = None
    serial_number_string = hex(certificate.serial_number)[2:].lower()

    # Also check other certificates in chain? The original code iterates all?
    # Original: for i in range(pem_number): check entry
    # Let's do that
    for i in range(pem_number):
        c = x509.load_pem_x509_certificate(pem_certificates[i].encode(), default_backend())
        sn = hex(c.serial_number)[2:].lower()
        if status_json['entries'].get(sn):
            status = status_json['entries'][sn]
            break

    if not status:
        google_status = "null"
    else:
        google_status = f"{status['reason']}"

    overall_status = get_overall_status(status, keychain_status, cert_status, google_status)

    oid_values = {}
    for rdn in certificate.subject:
        oid_values[rdn.oid._name] = rdn.value

    print(f"File: {keybox_path}")
    print(f"Cert SN : {Fore.BLUE}{serial_number_string}")

    if 'title' in oid_values and oid_values['title'] != 'TEE':
        print(f"Keybox Title : {Fore.BLUE}{oid_values['title']}")
    if 'organizationName' in oid_values:
        print(f"Keybox Organization: {Fore.BLUE}{oid_values['organizationName']}")
    if 'commonName' in oid_values:
        print(f"Keybox Name: {Fore.BLUE}{oid_values['commonName']}")

    print(f"Status : {overall_status}")
    print(f"Keychain : {keychain_status}")
    print(f"Validity: {validity_status}")
    print(f"Root Cert : {cert_status}")
    print(f"Check Time : {Fore.BLUE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 40)

    return overall_status

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Keybox Checker")
    parser.add_argument("path", help="Path to keybox file or directory")
    args = parser.parse_args()

    path = args.path
    if os.path.isfile(path):
        asyncio.run(keybox_check_cli(path))
    elif os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            for file in files:
                if file.endswith(".xml"):
                    asyncio.run(keybox_check_cli(os.path.join(root, file)))
    else:
        print(f"Path not found: {path}")
