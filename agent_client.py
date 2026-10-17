"""
Samba Agent Client for samba-web container.

Communicates with the host-level samba-agent daemon over a local Unix domain socket
(/run/samba-agent.sock). Replaces insecure nsenter and container privilege escalations.
"""

import os
import json
import socket
import logging
import subprocess

logger = logging.getLogger(__name__)

AGENT_SOCKET_PATH = os.environ.get("SAMBA_AGENT_SOCKET", "/run/samba-agent.sock")

class CompletedProcessLike:
    """Emulates subprocess.CompletedProcess for drop-in compatibility."""
    def __init__(self, args, returncode, stdout="", stderr=""):
        self.args = args
        self.returncode = returncode
        self.stdout = stdout or ""
        self.stderr = stderr or ""

def is_agent_available():
    """Checks if the Samba Host Agent Unix socket is accessible and responding."""
    if not os.path.exists(AGENT_SOCKET_PATH):
        return False
    try:
        res = send_request({"action": "ping"}, timeout=2.0)
        return bool(res and res.get("success") and res.get("pong"))
    except Exception:
        return False

def send_request(req, timeout=30.0):
    """Sends a single JSON request to the Unix socket and returns parsed response."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect(AGENT_SOCKET_PATH)
        payload = (json.dumps(req) + "\n").encode("utf-8")
        sock.sendall(payload)
        
        buffer = ""
        while True:
            chunk = sock.recv(4096).decode("utf-8", errors="ignore")
            if not chunk:
                break
            buffer += chunk
            if "\n" in buffer:
                line = buffer.split("\n", 1)[0].strip()
                if line:
                    return json.loads(line)
        return {"success": False, "error": "Empty response from agent"}
    finally:
        sock.close()

def agent_run_command(cmd, input=None, capture_output=True, text=True, check=False):
    """
    Executes a command via the host agent.
    Returns CompletedProcessLike or raises subprocess.CalledProcessError if check=True.
    """
    req = {
        "action": "run_command",
        "cmd": cmd,
        "input": input,
        "capture_output": capture_output,
        "text": text,
        "check": check
    }
    
    resp = send_request(req)
    if not resp.get("success") and "returncode" not in resp:
        # Agent rejected the command or failed before running
        err_msg = resp.get("error", "Unknown agent error")
        logger.error(f"Agent failed to execute {cmd}: {err_msg}")
        if check:
            raise subprocess.CalledProcessError(1, cmd, output="", stderr=err_msg)
        return CompletedProcessLike(cmd, 1, stdout="", stderr=err_msg)
        
    rc = resp.get("returncode", 0)
    stdout = resp.get("stdout", "")
    stderr = resp.get("stderr", "")
    
    if check and rc != 0:
        raise subprocess.CalledProcessError(rc, cmd, output=stdout, stderr=stderr)
        
    return CompletedProcessLike(cmd, rc, stdout=stdout, stderr=stderr)

def agent_path_exists(path):
    """Checks file/directory existence on the host via the agent."""
    req = {"action": "path_exists", "path": path}
    resp = send_request(req, timeout=5.0)
    if resp.get("success"):
        return resp.get("exists", False)
    return False
