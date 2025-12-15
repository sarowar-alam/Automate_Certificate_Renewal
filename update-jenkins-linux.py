import os
import glob
import logging
import sys
import paramiko
from pathlib import Path
from datetime import datetime

def configure_logging():
    """Configure basic logging to console"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )

def get_cert_files_path(cert_cn):
    """
    Search for JKS certificate files matching the given Common Name pattern.
    
    Args:
        cert_cn (str): Certificate Common Name (e.g., "*.my-company-name1.com")
    
    Returns:
        dict: Dictionary containing cert_dir and jks_path if found, None otherwise
    """
    # Replace wildcard with '!' for directory matching
    escaped_domain = cert_cn.replace('*', '!')
    # Get actual domain without wildcard for filename matching
    clean_domain = cert_cn.replace('*.', '')
    # Base path similar to Posh-ACME's structure
    base_path = Path(os.getenv('LOCALAPPDATA')) / 'Posh-ACME' / 'LE_PROD'
    
    try:
        # Search through all directories recursively
        for root, dirs, files in os.walk(base_path):
            # Look for the escaped domain directory
            cert_dir = Path(root) / escaped_domain
            
            # Search for JKS file with pattern jenkinsl.{clean_domain}.jks
            jks_pattern = f"jenkinsl.{clean_domain}.jks"
            jks_files = glob.glob(str(cert_dir / jks_pattern))
            
            if jks_files:
                jks_path = Path(jks_files[0])
                logging.info(f"Found existing JKS file in: {cert_dir}")
                return {
                    'cert_dir': str(cert_dir),
                    'jks_path': str(jks_path),
                    'clean_domain': clean_domain
                }
        
        logging.info(f"Could not find JKS file for CN: {cert_cn}")
        return None
    
    except Exception as e:
        logging.error(f"Error searching for certificate files: {str(e)}")
        return None

def transfer_jks_to_linux(jks_path, remote_ip, pem_path, clean_domain, timestamp):
    """
    Transfer JKS file to Linux server using paramiko
    
    Args:
        jks_path (str): Local path to JKS file
        remote_ip (str): Remote server IP
        pem_path (str): Path to PEM file for authentication
        clean_domain (str): Clean domain name for folder creation
        timestamp (str): Timestamp for folder naming
    
    Returns:
        str: Remote path where file was transferred, None if failed
    """
    username = "rocky"
    remote_folder = f"/home/{username}/cert_{timestamp}"
    remote_path = f"{remote_folder}/jenkinsl.{clean_domain}.jks"
    
    try:
        # Create SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect using PEM key
        logging.info(f"Connecting to {remote_ip} as {username}...")
        ssh.connect(hostname=remote_ip, username=username, key_filename=pem_path)
        
        # Create remote directory
        logging.info(f"Creating remote directory: {remote_folder}")
        stdin, stdout, stderr = ssh.exec_command(f"mkdir -p {remote_folder}")
        if stderr.read():
            raise Exception(f"Error creating directory: {stderr.read().decode()}")
        
        # Transfer file using SFTP
        logging.info(f"Transferring {jks_path} to {remote_path}")
        sftp = ssh.open_sftp()
        sftp.put(jks_path, remote_path)
        sftp.close()
        
        logging.info("File transfer completed successfully")
        return remote_path
        
    except Exception as e:
        logging.error(f"Error during file transfer: {str(e)}")
        return None
    finally:
        if 'ssh' in locals():
            ssh.close()

def deploy_jks_to_jenkins(ssh, clean_domain, timestamp):
    """
    Execute the deployment steps on the remote server with root privileges
    
    Args:
        ssh: Paramiko SSH client
        clean_domain: Domain name without wildcard
        timestamp: Timestamp string for backup files
    
    Returns:
        tuple: (success_status, backup_path) 
    """
    try:
        jenkins_cert_path = f"/var/lib/jenkins/certs/jenkinsl.{clean_domain}.jks"
        backup_path = f"{jenkins_cert_path}_backup_{timestamp}"
        rocky_path = f"/home/rocky/cert_{timestamp}/jenkinsl.{clean_domain}.jks"
        
        # 1. Check if file exists in Jenkins certs directory
        logging.info(f"Checking for existing JKS at {jenkins_cert_path}")
        stdin, stdout, stderr = ssh.exec_command(f"sudo test -f {jenkins_cert_path} && echo 'exists' || echo 'not found'")
        file_exists = stdout.read().decode().strip() == 'exists'
        
        # 2. Take backup if file exists
        if file_exists:
            logging.info(f"Creating backup: {backup_path}")
            stdin, stdout, stderr = ssh.exec_command(f"sudo cp {jenkins_cert_path} {backup_path}")
            if stderr.read():
                raise Exception(f"Backup failed: {stderr.read().decode()}")
        
        # 3. Copy new file (force replace)
        logging.info(f"Deploying new JKS file to {jenkins_cert_path}")
        stdin, stdout, stderr = ssh.exec_command(f"sudo cp -f {rocky_path} {jenkins_cert_path}")
        if stderr.read():
            raise Exception(f"Copy failed: {stderr.read().decode()}")
        
        # 4. Change file permissions
        logging.info("Updating file ownership...")
        stdin, stdout, stderr = ssh.exec_command(f"sudo chown jenkins:jenkins {jenkins_cert_path}")
        if stderr.read():
            raise Exception(f"chown failed: {stderr.read().decode()}")
        
        # 5. Restart Jenkins service
        logging.info("Restarting Jenkins service...")
        stdin, stdout, stderr = ssh.exec_command("sudo systemctl restart jenkins.service")
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            raise Exception(f"Jenkins restart failed with status {exit_status}")
        
        # Verify service status
        stdin, stdout, stderr = ssh.exec_command("sudo systemctl is-active jenkins.service")
        service_status = stdout.read().decode().strip()
        if service_status != "active":
            raise Exception(f"Jenkins service not active after restart. Status: {service_status}")
        
        logging.info("Jenkins service restarted successfully")
        return (True, backup_path if file_exists else None)
        
    except Exception as e:
        logging.error(f"Deployment error: {str(e)}")
        return (False, None)

def main():
    configure_logging()
    
    if len(sys.argv) < 3:
        logging.error("Usage: python script.py <CertificateCN> <RemoteIP> <PemPath>")
        logging.error("Example: python script.py *.my-company-name1.com 192.168.1.100 C:\\keys\\mykey.pem")
        sys.exit(1)
    
    cert_cn = sys.argv[1]
    remote_ip = sys.argv[2]
    pem_path = r"C:\KEYS\AmazonOregon.pem"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    logging.info(f"Searching for certificate: {cert_cn}")
    result = get_cert_files_path(cert_cn)
    
    if not result:
        print("\nNo matching certificate found.")
        sys.exit(1)
        
    print("\nCertificate found:")
    print(f"Directory: {result['cert_dir']}")
    print(f"JKS File: {result['jks_path']}")
    
    # Transfer to Linux server
    print("\nInitiating file transfer...")
    remote_path = transfer_jks_to_linux(
        result['jks_path'],
        remote_ip,
        pem_path,
        result['clean_domain'],
        timestamp
    )
    
    if not remote_path:
        print("\nFile transfer failed")
        sys.exit(1)
    
    print(f"\nFile successfully transferred to: {remote_path}")
    
    # Deploy to Jenkins
    print("\nStarting deployment to Jenkins...")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=remote_ip, username="rocky", key_filename=pem_path)
        
        success, backup_path = deploy_jks_to_jenkins(ssh, result['clean_domain'], timestamp)
        
        if success:
            print("\nDeployment completed successfully!")
            print(f"New cert deployed: /var/lib/jenkins/certs/jenkinsl.{result['clean_domain']}.jks")
            if backup_path:
                print(f"Backup created: {backup_path}")
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