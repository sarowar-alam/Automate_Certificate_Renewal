import os
import glob
import logging
import sys
import paramiko
from pathlib import Path
from datetime import datetime

def configure_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )

def get_cert_files_path(cert_cn):
    escaped_domain = cert_cn.replace('*', '!')
    clean_domain = cert_cn.replace('*.', '')    
    base_path = Path(os.getenv('LOCALAPPDATA')) / 'Posh-ACME' / 'LE_PROD'
    
    try:
        for root, _, _ in os.walk(base_path):
            cert_dir = Path(root) / escaped_domain
            if cert_dir.exists():
                # Verify required files exist
                required_files = {
                    'chain0': cert_dir / 'chain0.cer',
                    'cert': cert_dir / 'cert.cer',
                    'key': cert_dir / 'cert.key',
                    'fullchain': cert_dir / 'fullchain.cer'
                }
                
                if all(f.exists() for f in required_files.values()):
                    logging.info(f"Found certificate files in: {cert_dir}")
                    return {
                        'cert_dir': str(cert_dir),
                        'chain0': str(required_files['chain0']),
                        'cert': str(required_files['cert']),
                        'key': str(required_files['key']),
                        'fullchain': str(required_files['fullchain']),
                        'clean_domain': clean_domain,
                        'cert_cn': cert_cn
                    }
        
        logging.info(f"Could not find certificate files for CN: {cert_cn}")
        return None
    
    except Exception as e:
        logging.error(f"Error searching for certificate files: {str(e)}")
        return None

def deploy_to_zabbix(ssh, cert_files, timestamp):
    try:
        username = "rocky"
        remote_folder = f"/home/{username}/certificate_update_{timestamp}"
        ssl_backup = f"{remote_folder}/ssl_backup.zip"
        
        # Create remote directory
        logging.info(f"Creating remote directory: {remote_folder}")
        stdin, stdout, stderr = ssh.exec_command(f"mkdir -p {remote_folder}")
        if stderr.read():
            raise Exception(f"Error creating directory: {stderr.read().decode()}")
        
        # Transfer certificate files
        sftp = ssh.open_sftp()
        try:
            logging.info("Transferring certificate files...")
            remote_files = {
                'chain0': f"{remote_folder}/chain0.cer",
                'cert': f"{remote_folder}/cert.cer",
                'key': f"{remote_folder}/cert.key",
                'fullchain': f"{remote_folder}/fullchain.cer"
            }
            
            for file_type in remote_files:
                sftp.put(cert_files[file_type], remote_files[file_type])
        finally:
            sftp.close()
        
        # Create backup of current SSL files
        logging.info("Creating backup of current SSL configuration")
        stdin, stdout, stderr = ssh.exec_command(
            f"sudo zip -jr {ssl_backup} /etc/httpd/ssl/*"
        )
        if stderr.read():
            raise Exception(f"Backup failed: {stderr.read().decode()}")
        
        # Deploy new certificates with proper names
        domain_prefix = cert_files['cert_cn'].replace('*.', 'star_').replace('.', '_')
        deploy_commands = [
            f"sudo cp {remote_folder}/chain0.cer /etc/httpd/ssl/CACert.crt",
            f"sudo cp {remote_folder}/cert.cer /etc/httpd/ssl/{domain_prefix}.crt",
            f"sudo cp {remote_folder}/cert.key /etc/httpd/ssl/{domain_prefix}.key",
            f"sudo cp {remote_folder}/fullchain.cer /etc/httpd/ssl/{domain_prefix}.pem",
            f"sudo chmod 644 /etc/httpd/ssl/*.crt",
            f"sudo chmod 644 /etc/httpd/ssl/*.pem",
            f"sudo chmod 600 /etc/httpd/ssl/*.key",
            f"sudo chown root:root /etc/httpd/ssl/*"
        ]
        
        for cmd in deploy_commands:
            logging.info(f"Executing: {cmd}")
            stdin, stdout, stderr = ssh.exec_command(cmd)
            if stderr.read():
                raise Exception(f"Command failed: {cmd} - {stderr.read().decode()}")
        
        # Restart services
        services = ["zabbix-server", "httpd"]
        for service in services:
            logging.info(f"Restarting {service} service")
            stdin, stdout, stderr = ssh.exec_command(f"sudo systemctl restart {service}.service")
            exit_status = stdout.channel.recv_exit_status()
            if exit_status != 0:
                raise Exception(f"Service restart failed: {service}")
            
            # Verify service status
            stdin, stdout, stderr = ssh.exec_command(f"sudo systemctl is-active {service}.service")
            service_status = stdout.read().decode().strip()
            if service_status != "active":
                raise Exception(f"Service not active: {service}. Status: {service_status}")
        
        logging.info("Zabbix certificate deployment completed successfully")
        return True
        
    except Exception as e:
        logging.error(f"Deployment error: {str(e)}")
        return False

def main():
    configure_logging()
    
    if len(sys.argv) < 3:
        logging.error("Usage: python script.py <CertificateCN> <RemoteIP> <PemPath>")
        logging.error("Example: python script.py *.my-company-name.net 192.168.1.100 C:\\keys\\mykey.pem")
        sys.exit(1)
    
    cert_cn = sys.argv[1]
    remote_ip = sys.argv[2]
    pem_path = r"C:\KEYS\EUwest.pem"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    logging.info(f"Searching for certificate: {cert_cn}")
    cert_files = get_cert_files_path(cert_cn)
    
    if not cert_files:
        print("\nNo matching certificate files found.")
        sys.exit(1)
        
    print("\nCertificate files found:")
    for k, v in cert_files.items():
        if k not in ['clean_domain', 'cert_cn']:
            print(f"{k}: {v}")
    
    # Connect and deploy to Zabbix server
    print("\nInitiating Zabbix server deployment...")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=remote_ip, username="rocky", key_filename=pem_path)
        
        if deploy_to_zabbix(ssh, cert_files, timestamp):
            domain_prefix = cert_files['cert_cn'].replace('*.', 'star_').replace('.', '_')
            print("\nDeployment completed successfully!")
            print(f"Backup created: /home/rocky/certificate_update_{timestamp}/ssl_backup.zip")
            print(f"New certificates deployed:")
            print(f"  /etc/httpd/ssl/CACert.crt")
            print(f"  /etc/httpd/ssl/{domain_prefix}.crt")
            print(f"  /etc/httpd/ssl/{domain_prefix}.key")
            print(f"  /etc/httpd/ssl/{domain_prefix}.pem")
            print("\nServices restarted: zabbix-server, httpd")
            sys.exit(0)
        else:
            print("\nDeployment failed")
            sys.exit(1)
            
    except Exception as e:
        logging.error(f"SSH operation failed: {str(e)}")
        sys.exit(1)
    finally:
        if 'ssh' in locals():
            ssh.close()

if __name__ == "__main__":
    main()