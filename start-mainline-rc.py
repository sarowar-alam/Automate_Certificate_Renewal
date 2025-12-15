import boto3
import sys
import time
import ast  # <--- Import to safely parse the list string

def wait_for_checks(ec2_client, instance_id, timeout=600, interval=15):
    waited = 0
    while waited < timeout:
        try:
            statuses = ec2_client.describe_instance_status(InstanceIds=[instance_id], IncludeAllInstances=True)
            if not statuses['InstanceStatuses']:
                print(f"[INFO] No status available yet for {instance_id}, waiting...")
            else:
                status = statuses['InstanceStatuses'][0]
                system_status = status['SystemStatus']['Status']
                instance_status = status['InstanceStatus']['Status']
                print(f"[INFO] {instance_id} -> SystemStatus={system_status}, InstanceStatus={instance_status}")

                if system_status == 'ok' and instance_status == 'ok':
                    return True
        except Exception as e:
            print(f"[ERROR] Exception while checking status for {instance_id}: {e}")

        time.sleep(interval)
        waited += interval

    return False

def start_instance(access_key, secret_key, region, instance_ids):
    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        ec2 = session.client('ec2')

        print(f"Starting instances: {', '.join(instance_ids)}")
        ec2.start_instances(InstanceIds=instance_ids)

        print("Waiting for instances to be running...")
        waiter = ec2.get_waiter('instance_running')
        waiter.wait(InstanceIds=instance_ids)
        print("Instances are running.")

        all_ok = True
        for instance_id in instance_ids:
            print(f"Waiting for status checks for {instance_id}...")
            if wait_for_checks(ec2, instance_id):
                print(f"Instance {instance_id} passed all checks.")
            else:
                print(f"[FAILED] Instance {instance_id} failed status checks.")
                all_ok = False

        return 0 if all_ok else 1

    except Exception as e:
        print(f"[ERROR] Failed to start instances or check status: {e}")
        return 1

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python start_instance.py <access_key> <secret_key> <region> \"['i-abc123', 'i-def456']\"")
        sys.exit(1)

    access_key  = sys.argv[1]
    secret_key  = sys.argv[2]
    region      = sys.argv[3]

    try:
        instance_ids = ast.literal_eval(sys.argv[4])
        if not isinstance(instance_ids, list):
            raise ValueError("Instance IDs must be a list.")
    except Exception as e:
        print(f"[ERROR] Invalid instance ID list format: {e}")
        sys.exit(1)

    exit(start_instance(access_key, secret_key, region, instance_ids))
