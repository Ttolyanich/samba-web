#!/usr/bin/env python3
"""
Samba Web Host Agent (Zero-Dependency Unix Domain Socket Daemon)

Runs natively on the Linux host as a systemd service.
Accepts structured commands exclusively via a local Unix domain socket
from the sterilized samba-web Docker container.

Enforces strict whitelisting of binaries and validates actions to prevent
any privilege escalation or arbitrary command execution.
"""

import os
import sys
import json
import socket
import select
import signal
import subprocess
import logging

LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [SambaAgent] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("SambaAgent")

SOCKET_PATH = os.environ.get("SAMBA_AGENT_SOCKET", "/run/samba-agent/samba-agent.sock")
ALLOWED_BINARIES = {
    "pdbedit",
    "id",
    "groupadd",
    "gpasswd",
    "smbpasswd",
    "usermod",
    "useradd",
    "getfacl",
    "stat",
    "getent",
    "find",
    "smbstatus",
    "kill",
    "test"
}

def is_pid_smbd(pid_str):
    """Checks if the given PID actually belongs to an smbd process."""
    try:
        pid = int(pid_str)
        comm_path = f"/proc/{pid}/comm"
        if os.path.exists(comm_path):
            with open(comm_path, "r", encoding="utf-8") as f:
                comm = f.read().strip()
                return comm == "smbd"
        cmdline_path = f"/proc/{pid}/cmdline"
        if os.path.exists(cmdline_path):
            with open(cmdline_path, "rb") as f:
                cmdline = f.read().decode("utf-8", errors="ignore")
                return "smbd" in cmdline
        return True # Process may have already exited
    except Exception as e:
        logger.warning(f"Error checking PID {pid_str}: {e}")
        return False

def validate_command(cmd):
    """
    Validates that the command uses an allowed binary and adheres to security constraints.
    Returns (cleaned_cmd, error_message).
    """
    if not isinstance(cmd, list) or not cmd:
        return None, "Command must be a non-empty list of arguments"
    
    # Strip leading sudo if present
    base_cmd = list(cmd)
    if base_cmd[0] == "sudo":
        base_cmd = base_cmd[1:]
    
    if not base_cmd:
        return None, "Empty command after stripping sudo"
        
    binary = os.path.basename(base_cmd[0])
    if binary not in ALLOWED_BINARIES:
        return None, f"Binary '{binary}' is not permitted by agent whitelist"
    
    # Extra validation for kill command
    if binary == "kill":
        # Check target PID
        pids = [arg for arg in base_cmd[1:] if arg.isdigit()]
        for p in pids:
            if not is_pid_smbd(p):
                return None, f"Permission denied: kill is only permitted for smbd processes (PID {p} is not smbd)"
                
    return base_cmd, None

def handle_request(req):
    """Processes a single JSON RPC request."""
    action = req.get("action")
    
    if action == "ping":
        return {"success": True, "pong": True, "version": "1.0.0"}
        
    elif action == "path_exists":
        path = req.get("path")
        if not path or not isinstance(path, str):
            return {"success": False, "error": "Invalid path"}
        return {"success": True, "exists": os.path.exists(path)}
        
    elif action == "run_command":
        cmd = req.get("cmd")
        valid_cmd, err = validate_command(cmd)
        if err:
            logger.warning(f"Rejected command request: {cmd} -> {err}")
            return {"success": False, "error": err}
            
        capture_output = req.get("capture_output", True)
        text = req.get("text", True)
        stdin_input = req.get("input", None)
        check = req.get("check", False)
        
        try:
            res = subprocess.run(
                valid_cmd,
                input=stdin_input,
                capture_output=capture_output,
                text=text,
                check=check
            )
            return {
                "success": True,
                "returncode": res.returncode,
                "stdout": res.stdout if capture_output else "",
                "stderr": res.stderr if capture_output else ""
            }
        except subprocess.CalledProcessError as e:
            return {
                "success": False,
                "returncode": e.returncode,
                "stdout": e.stdout if hasattr(e, "stdout") and e.stdout else "",
                "stderr": e.stderr if hasattr(e, "stderr") and e.stderr else str(e),
                "error": str(e)
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
            
    else:
        return {"success": False, "error": f"Unknown action '{action}'"}

def run_server():
    socket_dir = os.path.dirname(SOCKET_PATH)
    if socket_dir and not os.path.exists(socket_dir):
        os.makedirs(socket_dir, mode=0o755, exist_ok=True)
        
    if os.path.exists(SOCKET_PATH):
        try:
            os.unlink(SOCKET_PATH)
        except OSError:
            pass

    server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server_sock.bind(SOCKET_PATH)
    # Grant rw-rw-rw- permissions so the docker container (unprivileged UID) can communicate
    os.chmod(SOCKET_PATH, 0o666)
    server_sock.listen(16)
    
    logger.info(f"Samba Host Agent started. Listening on Unix socket: {SOCKET_PATH}")

    def cleanup(*args):
        logger.info("Stopping Samba Host Agent...")
        try:
            server_sock.close()
            if os.path.exists(SOCKET_PATH):
                os.unlink(SOCKET_PATH)
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)

    while True:
        try:
            client_sock, _ = server_sock.accept()
            try:
                client_sock.settimeout(30.0)
                buffer = ""
                while True:
                    chunk = client_sock.recv(4096).decode("utf-8", errors="ignore")
                    if not chunk:
                        break
                    buffer += chunk
                    if "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.strip()
                        if line:
                            try:
                                req = json.loads(line)
                                resp = handle_request(req)
                            except Exception as ex:
                                resp = {"success": False, "error": f"Invalid JSON or handler error: {ex}"}
                            
                            client_sock.sendall((json.dumps(resp) + "\n").encode("utf-8"))
            except Exception as e:
                logger.error(f"Client connection error: {e}")
            finally:
                client_sock.close()
        except Exception as e:
            logger.error(f"Server accept error: {e}")

if __name__ == "__main__":
    run_server()
