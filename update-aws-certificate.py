import boto3
import sys
from botocore.exceptions import ClientError, BotoCoreError
import os
import glob

def reimport_certificate(access_key, secret_key, region, certificate_arn, cert_path, key_path, chain_path):
    try:
        # Validate file existence
        if not os.path.isfile(cert_path):
            raise FileNotFoundError(f"Certificate file not found: {cert_path}")
        if not os.path.isfile(key_path):
            raise FileNotFoundError(f"Private key file not found: {key_path}")
        if chain_path and not os.path.isfile(chain_path):
            raise FileNotFoundError(f"Certificate chain file not found: {chain_path}")

        # Read certificate files
        with open(cert_path, 'rb') as f:
            certificate_body = f.read()

        with open(key_path, 'rb') as f:
            private_key = f.read()

        certificate_chain = None
        if chain_path:
            with open(chain_path, 'rb') as f:
                certificate_chain = f.read()

        # Create session and ACM client
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        client = session.client('acm')

        # Reimport certificate
        if certificate_chain:
            response = client.import_certificate(
                CertificateArn=certificate_arn,
                Certificate=certificate_body,
                PrivateKey=private_key,
                CertificateChain=certificate_chain
            )
        else:
            response = client.import_certificate(
                CertificateArn=certificate_arn,
                Certificate=certificate_body,
                PrivateKey=private_key
            )

        print(f"Certificate reimported successfully in region {region}")
        return response['CertificateArn']

    except FileNotFoundError as fnf_error:
        print(f"File error: {fnf_error}")
        sys.exit(1)
    except ClientError as e:
        print(f"AWS ClientError: {e.response['Error']['Message']}")
        sys.exit(1)
    except BotoCoreError as e:
        print(f"BotoCoreError: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        sys.exit(1)

def get_all_imported_cert_arns(domain_name, access_key, secret_key, regions):
    matches = []

    for region in regions:
        try:
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region
            )
            client = session.client('acm')

            status_filter = ['ISSUED', 'EXPIRED']
            paginator = client.get_paginator('list_certificates')

            for page in paginator.paginate(CertificateStatuses=status_filter):
                for cert_summary in page.get('CertificateSummaryList', []):
                    cert_arn = cert_summary['CertificateArn']
                    try:
                        cert_details = client.describe_certificate(CertificateArn=cert_arn)['Certificate']
                    except ClientError as e:
                        print(f"Skipping certificate {cert_arn} in {region} due to describe error: {e.response['Error']['Message']}")
                        continue
                    except BotoCoreError as e:
                        print(f"BotoCoreError while describing certificate {cert_arn} in {region}: {str(e)}")
                        continue

                    if (
                        cert_details['DomainName'] == domain_name and
                        cert_details['Type'] == 'IMPORTED' and
                        cert_details.get('RenewalEligibility') == 'INELIGIBLE' and
                        cert_details['Status'] in ['ISSUED', 'EXPIRED']
                    ):
                        matches.append({
                            'CertificateArn': cert_arn,
                            'Region': region
                        })

        except ClientError as e:
            print(f"ClientError accessing ACM in region {region}: {e.response['Error']['Message']}")
            sys.exit(1)
        except BotoCoreError as e:
            print(f"BotoCoreError in region {region}: {str(e)}")
            sys.exit(1)
        except Exception as e:
            print(f"Unexpected error in region {region}: {str(e)}")
            sys.exit(1)

    return matches

def get_file_path(base_path, filename):
    path = os.path.join(base_path, filename)
    if os.path.isfile(path):
        print(f"[FOUND] {filename} path: {path}")
        return path
    else:
        print(f"[ERROR] {filename} not found at {path}")
        return None

# Main Script
if __name__ == "__main__":

    if len(sys.argv) < 3:
        print("Usage: python script.py <access_key> <secret_key> <domain>")
        sys.exit(1)

    access_key = sys.argv[1]
    secret_key = sys.argv[2]
    domain     = sys.argv[3]

    regions = ['us-west-2', 'us-east-1']

    escaped_domain = domain.replace('*', '!')
    base_dir = os.environ.get("LOCALAPPDATA")
    cert_glob_path = os.path.join(base_dir, "Posh-ACME", "LE_PROD", "*", escaped_domain)

    matches = glob.glob(cert_glob_path)
    if matches:
        existing_path = matches[0]
        print(f"[FOUND] Existing path: {existing_path}")

        cert_path  = get_file_path(existing_path, "cert.cer")
        key_path   = get_file_path(existing_path, "cert.key")
        chain_path = get_file_path(existing_path, "CAcert.crt")

        if not all([cert_path, key_path, chain_path]):
            print("[FATAL] One or more required certificate files are missing.")
            sys.exit(1)
    else:
        print("[ERROR] No matching path found.")
        sys.exit(1)

    results = get_all_imported_cert_arns(domain, access_key, secret_key, regions)
    if results:
        for cert in results:
            print(f"Certificate ARN: {cert['CertificateArn']} found in {cert['Region']}")
            arn = reimport_certificate(
                access_key,
                secret_key,
                cert['Region'],
                cert['CertificateArn'],
                cert_path,
                key_path,
                chain_path
            )
            if arn:
                print(f"Updated certificate ARN: {arn}")
            else:
                print("Reimport failed.")
                sys.exit(1)
    else:
        print("No matching certificates found.")
        sys.exit(0)

    sys.exit(0)  # Success
