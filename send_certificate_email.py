import os
import glob
import sys
import boto3
import subprocess
from datetime import datetime
from email.utils import parseaddr

def main(domain, to_list, cc_list, aws_key, aws_secret, region,
         aws_key_2, aws_secret_2, bucket_name, prefix):

    if not domain:
        print("[ERROR] Domain is required.")
        sys.exit(1)

    # Step 1: Locate the certificate directory
    escaped_domain = domain.replace("*", "!")
    cert_glob_path = os.path.expandvars(fr"%LOCALAPPDATA%\Posh-ACME\LE_PROD\*\{escaped_domain}")
    matches = glob.glob(cert_glob_path)

    if not matches:
        print(f"[ERROR] No matching path found for domain: {escaped_domain}")
        sys.exit(1)

    cert_dir = matches[0]
    print(f"[INFO] Found certificate path: {cert_dir}")

    # Step 2: Verify required files exist
    required_exts = [".pfx", ".cer", ".key"]
    missing = [ext for ext in required_exts if not any(f.endswith(ext) for f in os.listdir(cert_dir))]
    if missing:
        print(f"[ERROR] Missing certificate files: {missing}")
        sys.exit(1)

    # Step 3: Zip the contents
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    safe_domain = domain.replace("*", "_").replace(".", "_")
    zip_filename = f"{safe_domain}_certificate_{timestamp}.zip"
    zip_path = os.path.join("C:\\temp", zip_filename)

    seven_zip = r"C:\Program Files\7-Zip\7z.exe"
    subprocess.run([seven_zip, 'a', zip_path, f"{cert_dir}\\*"], check=True)
    print(f"[INFO] Created zip: {zip_path}")

    # Step 4: Upload to S3 and get pre-signed URL
    pre_signed_url = upload_to_s3_and_get_url(
        aws_key_2, aws_secret_2, region, bucket_name, prefix, zip_path, zip_filename
    )

    # Step 5: Parse and send email with download link
    to_addresses = [addr.strip() for addr in to_list.split(";") if parseaddr(addr)[1]]
    cc_addresses = [addr.strip() for addr in cc_list.split(";") if parseaddr(addr)[1]]

    session = boto3.Session(
        aws_access_key_id=aws_key,
        aws_secret_access_key=aws_secret,
        region_name=region
    )
    ses_client = session.client('ses')

    from_email = 'DevOps Automated_Certificate <noreply@my-company-name.net>'
    subject = f"Updated Certificate of {domain}"
    body_text = f"""Hello Team,

The updated certificate for domain {domain} is now available at the secure link below:

{pre_signed_url}

This link will expire in 7 days.

Regards,
DevOps Team
"""

    # Send plain email without attachment
    response = ses_client.send_email(
        Source=from_email,
        Destination={
            'ToAddresses': to_addresses,
            'CcAddresses': cc_addresses
        },
        Message={
            'Subject': {'Data': subject},
            'Body': {
    'Html': {
        'Data': f"""
        <html>
            <body>
                <p>Hello Team,</p>
                <p>The updated certificate for domain <strong>{domain}</strong> is now available at the secure link below:</p>
                <p><a href="{pre_signed_url}">Download {domain} Certificate</a></p>
                <p>This link will expire in 7 days.</p>
                <p>Regards,<br>DevOps Team</p>
            </body>
        </html>
        """
    }
}

        }
    )
    print(f"[INFO] Email sent. SES Message ID: {response['MessageId']}")


def upload_to_s3_and_get_url(aws_key, aws_secret, region, bucket, prefix, zip_path, zip_filename):
    session = boto3.Session(
        aws_access_key_id=aws_key,
        aws_secret_access_key=aws_secret,
        region_name=region
    )
    s3 = session.client('s3')

    s3_key = f"{prefix.rstrip('/')}/{zip_filename}"

    s3.upload_file(zip_path, bucket, s3_key)
    print(f"[INFO] Uploaded to s3://{bucket}/{s3_key}")

    # Generate a 7-day pre-signed URL
    url = s3.generate_presigned_url(
        ClientMethod='get_object',
        Params={'Bucket': bucket, 'Key': s3_key},
        ExpiresIn=604800  # 7 days
    )
    print(f"[INFO] Pre-signed URL: {url}")
    return url


if __name__ == "__main__":
    if len(sys.argv) != 11:
        print("Usage:")
        print("python send_certificate_email.py <domain> <to_list> <cc_list> "
              "<aws_key> <aws_secret> <region> "
              "<aws_key_2> <aws_secret_2> <bucket> <prefix>")
        sys.exit(1)

    main(*sys.argv[1:])
