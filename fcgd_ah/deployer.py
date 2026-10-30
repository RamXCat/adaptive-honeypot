"""
deployer.py
SFTP deployment helper. Reads all SSH credentials from environment variables.
Never hardcodes credentials.
"""

import os


def deploy_to_target(artifact_content: str, remote_path: str) -> None:
    """
    SFTPs artifact_content to the configured honeypot target machine.
    Requires the following environment variables to be set:
        TARGET_HOST         - IP or hostname of the honeypot machine
        TARGET_SSH_USER     - SSH username
        TARGET_SSH_PASSWORD - SSH password
    Raises EnvironmentError if any variable is unset.
    """
    host     = os.environ.get("TARGET_HOST")
    user     = os.environ.get("TARGET_SSH_USER")
    password = os.environ.get("TARGET_SSH_PASSWORD")

    missing = [k for k, v in [
        ("TARGET_HOST", host),
        ("TARGET_SSH_USER", user),
        ("TARGET_SSH_PASSWORD", password),
    ] if not v]

    if missing:
        raise EnvironmentError(
            f"Cannot deploy: missing required environment variable(s): {', '.join(missing)}. "
            f"Set them before calling deploy_to_target()."
        )

    # Import paramiko only when deployment is actually invoked
    import paramiko

    transport = paramiko.Transport((host, 22))
    try:
        transport.connect(username=user, password=password)
        sftp = paramiko.SFTPClient.from_transport(transport)

        # Normalise ~ in remote path
        if remote_path.startswith("~"):
            remote_path = remote_path.replace("~", f"/home/{user}", 1)

        # Ensure parent directory exists
        parent = "/".join(remote_path.split("/")[:-1])
        if parent:
            try:
                sftp.mkdir(parent)
            except OSError:
                pass  # Directory already exists

        with sftp.file(remote_path, "w") as f:
            f.write(artifact_content)

        sftp.close()
        print(f"[+] Deployed artifact to {host}:{remote_path}")
    finally:
        transport.close()
