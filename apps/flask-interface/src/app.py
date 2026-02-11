# Test
#! /usr/bin/env python3

from flask import (
    Flask,
    request,
    jsonify,
    abort,
    current_app,
    g,
    make_response,
    render_template,
    redirect,
    url_for,
)
import secrets
import psutil
import socket
import subprocess
from functools import wraps
import hmac
import hashlib
from datetime import datetime, timedelta
import jwt
import os
import json
import logging
import time
from prometheus_client import Counter, Histogram, Gauge, generate_latest, REGISTRY

# Ansible control config

ANSIBLE_CONTROL_NODE_HOST = os.getenv("ANSIBLE_CONTROL_NODE_HOST")
ANSIBLE_CONTROL_NODE_USER = os.getenv("ANSIBLE_CONTROL_NODE_USER", "ec2-user")
ANSIBLE_SSH_KEY_PATH = os.getenv("ANSIBLE_SSH_KEY_PATH", "/secrets/ssh-private-key")
ANSIBLE_BASE_DIR = os.getenv("ANSIBLE_BASE_DIR", "/home/ec2-user/ansible")
ANSIBLE_PLAYBOOK_DIR = os.getenv(
    "ANSIBLE_PLAYBOOK_DIR", f"{ANSIBLE_BASE_DIR}/playbooks"
)
ANSIBLE_INVENTORY_PATH = os.getenv(
    "ANSIBLE_INVENTORY_PATH", f"{ANSIBLE_BASE_DIR}/inventory/inventory.yml"
)


ALLOWED_PLAYBOOKS = {
    "ping": "ping.yml",
}

HASH_SECRET = os.getenv("HASH_SECRET", "dev-secret-change-me").encode()
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me").encode()

logging.basicConfig(level=logging.INFO)

# -----------------------
# Prometheus Metrics
# -----------------------

ANSIBLE_JOBS_TOTAL = Counter(
    "ansible_jobs_total",
    "Total number of Ansible jobs",
    ["playbook", "status", "user"],
)

ANSIBLE_JOB_DURATION = Histogram(
    "ansible_job_duration_seconds",
    "Duration of Ansible jobs",
    ["playbook"],
)

ANSIBLE_JOBS_RUNNING = Gauge(
    "ansible_jobs_running",
    "Number of currently running Ansible jobs",
)


# API key hashing
def hash_key(api_key: str) -> str:
    """
    hash_key("secretapikey123")
    'a9be16b5989c1cffc7e91a81143c6053362340717cbfc98b3a07ffcbe931f396'

    hash_key('secretapikey1')
    'deda7fdcf493cae490ea6b7889bc032799d5c1459085cd59bcb6f38ff6f4045a'

    hash_key('abc123')
    '8e024929eb9be0f39c3fb4e0f58bb5f2e8c9ccf81d1723e4c78729d3d0b135f0'

    hash_key("password1")
    '6cbfeac955cd5296ec7394a3d845c0b2f53603fb6fd49629b2b6371bf39ab4f7'

    hash_key("password2")
    'a3a232a44f8017ae2d673ae57b5b132f5153d1f117e89008e2f6098f2880a2f2'
    """
    return hmac.new(HASH_SECRET, api_key.encode(), hashlib.sha256).hexdigest()


def keys_match(api_key: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_key(api_key), stored_hash)


def run_remote_ansible_playbook(
    playbook_name: str, extra_vars: dict = None, user: str = "unknown"
) -> dict:
    """
    Execute an Ansible playbook on the remote Ansible control node via SSH.

    """

    ANSIBLE_JOBS_RUNNING.inc()
    start_time = time.time()

    if not ANSIBLE_CONTROL_NODE_HOST:
        logging.error("ANSIBLE_CONTROL_NODE_HOST not configured")
        ANSIBLE_JOBS_RUNNING.dec()
        ANSIBLE_JOBS_TOTAL.labels(
            playbook=playbook_name, status="failed", user=user
        ).inc()
        return {
            "status": "failed",
            "rc": 1,
            "error": "Ansible control node not configured",
            "stdout": "",
            "stderr": "ANSIBLE_CONTROL_NODE_HOST environment variable not set",
        }

    # Build the ansible-playbook command
    playbook_path = f"{ANSIBLE_PLAYBOOK_DIR}/{playbook_name}"
    cmd_parts = [
        "ansible-playbook",
        playbook_path,
        "-i",
        ANSIBLE_INVENTORY_PATH,
    ]

    # Add extra vars if provided
    if extra_vars:
        extra_vars_json = json.dumps(extra_vars)
        cmd_parts.extend(["--extra-vars", f"'{extra_vars_json}'"])

    # Build the full command to run on remote host
    remote_command = " ".join(cmd_parts)

    # SSH command to execute on the Ansible control node
    ssh_cmd = [
        "ssh",
        "-i",
        ANSIBLE_SSH_KEY_PATH,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        f"{ANSIBLE_CONTROL_NODE_USER}@{ANSIBLE_CONTROL_NODE_HOST}",
        remote_command,
    ]

    logging.info(
        f"Executing remote playbook: {playbook_name} on {ANSIBLE_CONTROL_NODE_HOST}"
    )

    try:
        # Execute SSH command
        result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
        )

        # Record metrics
        duration = time.time() - start_time
        status = "successful" if result.returncode == 0 else "failed"

        ANSIBLE_JOBS_RUNNING.dec()
        ANSIBLE_JOB_DURATION.labels(playbook=playbook_name).observe(duration)
        ANSIBLE_JOBS_TOTAL.labels(
            playbook=playbook_name, status=status, user=user
        ).inc()

        return {
            "status": status,
            "rc": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired:
        logging.error(f"Playbook execution timeout: {playbook_name}")

        # Record metrics for timeout
        duration = time.time() - start_time
        ANSIBLE_JOBS_RUNNING.dec()
        ANSIBLE_JOB_DURATION.labels(playbook=playbook_name).observe(duration)
        ANSIBLE_JOBS_TOTAL.labels(
            playbook=playbook_name, status="failed", user=user
        ).inc()

        return {
            "status": "failed",
            "rc": -1,
            "error": "Playbook execution timeout",
            "stdout": "",
            "stderr": "Command timed out after 300 seconds",
        }
    except Exception as e:
        logging.error(f"Error executing playbook: {str(e)}")

        # Record metrics for error
        duration = time.time() - start_time
        ANSIBLE_JOBS_RUNNING.dec()
        ANSIBLE_JOB_DURATION.labels(playbook=playbook_name).observe(duration)
        ANSIBLE_JOBS_TOTAL.labels(
            playbook=playbook_name, status="failed", user=user
        ).inc()

        return {
            "status": "failed",
            "rc": -1,
            "error": str(e),
            "stdout": "",
            "stderr": str(e),
        }


app = Flask(__name__)

# -----------------------
# In-memory data store
# -----------------------
data = {"interfaces": {}, "notes": {}}

# In-memory user/key database
user_db = {
    "alice": {
        "api_key": [
            "deda7fdcf493cae490ea6b7889bc032799d5c1459085cd59bcb6f38ff6f4045a"
        ],  # secretapikey1
        "role": "admin",
        "password": "6cbfeac955cd5296ec7394a3d845c0b2f53603fb6fd49629b2b6371bf39ab4f7",  # password1
    },
    "bob": {
        "api_key": [
            "8e024929eb9be0f39c3fb4e0f58bb5f2e8c9ccf81d1723e4c78729d3d0b135f0"
        ],  # abc123
        "role": "user",
        "password": "a3a232a44f8017ae2d673ae57b5b132f5153d1f117e89008e2f6098f2880a2f2",  # password2
    },
}


def jwt_protected(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("jwt")
        if not token:
            abort(401, description="Not Logged In")
        try:
            g.jwt_payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            payload = {
                "username": g.jwt_payload["username"],
                "exp": datetime.utcnow() + timedelta(minutes=1),
            }
            token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        except jwt.ExpiredSignatureError:
            abort(401, description="Token Expired")
        except jwt.InvalidTokenError:
            abort(401, description="Invalid Token")
        response = func(*args, **kwargs)
        response.set_cookie("jwt", token, httponly=True, samesite="Lax")
        return response

    return wrapper


@app.errorhandler(401)
def unauthorized(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": e.description}), 401
    return render_template(
        "error.html",
        error_code=401,
        error_title="Unauthorized",
        error_message=e.description or "You need to log in to access this page",
    ), 401


@app.errorhandler(404)
def not_found(e):
    return render_template(
        "error.html",
        error_code=404,
        error_title="Not Found",
        error_message="The page you are looking for does not exist",
    ), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template(
        "error.html",
        error_code=500,
        error_title="Internal Server Error",
        error_message="Something went wrong on our end",
    ), 500


def api_protected(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        current_app.logger.info("api_protected running")

        auth = request.headers.get("Authorization", "")
        username = request.headers.get("Username", "")

        if not username:
            abort(401, description="Missing Username header")

        if auth.startswith("Bearer "):
            key = auth.split(" ", 1)[1]
            info = user_db.get(username)

            for v in info.get("api_key", []):
                if keys_match(key, v):
                    return func(*args, **kwargs)

        abort(401, description="Invalid or missing API key or username")

    return wrapper


@app.route("/api/ansible/run", methods=["POST"])
@api_protected
def run_ansible():
    """
    Run a predefined Ansible playbook on remote control node.

    JSON body:
    {
        "playbook": "ping",
        "extra_vars": {
            "replicas": 3
        }
    }
    """

    body = request.json or {}
    playbook_key = body.get("playbook")
    extra_vars = body.get("extra_vars", {})
    username = request.headers.get("Username", "unknown")

    if playbook_key not in ALLOWED_PLAYBOOKS:
        return jsonify({"error": "Playbook not allowed"}), 400

    playbook_file = ALLOWED_PLAYBOOKS[playbook_key]

    # Execute playbook on remote Ansible control node
    result = run_remote_ansible_playbook(playbook_file, extra_vars, user=username)

    return jsonify(
        {
            "status": result["status"],
            "rc": result["rc"],
            "stdout": result["stdout"],
            "stderr": result["stderr"],
        }
    )


def load_data():
    data["interfaces"] = {}

    for iface, addrs in psutil.net_if_addrs().items():
        data["interfaces"][iface] = []

        for a in addrs:
            fam = "MAC"
            if a.family == socket.AF_INET:
                fam = "IPv4"
            elif a.family == socket.AF_INET6:
                fam = "IPv6"

            data["interfaces"][iface].append({"family": fam, "address": a.address})


load_data()


@app.route("/")
def index():
    """Home page"""
    return render_template("index.html")


@app.route("/login", methods=["POST", "GET"])
def login():
    """ """
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if user_db.get(username)["password"] == hash_key(password):
            payload = {
                "username": username,
                "exp": datetime.utcnow() + timedelta(minutes=1),
            }
            token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
            resp = make_response(redirect(url_for("dashboard")))
            resp.status_code = 302
            resp.set_cookie("jwt", token, httponly=True, samesite="Lax")
            return resp
        abort(401, description="Invalid credentials")
    if request.method == "GET":
        token = request.cookies.get("jwt")
        if token:
            try:
                g.jwt_payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
                return redirect(url_for("dashboard"))
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                pass
        return make_response(render_template("login.html", error=error))


@app.route("/dashboard")
@jwt_protected
def dashboard():
    """Dashboard page - requires JWT authentication"""
    username = g.jwt_payload.get("username")
    api_keys = user_db.get(username, {}).get("api_key", [])
    message = request.args.get("message")

    # wrap render_template in make_response so jwt_protected can set cookie
    return make_response(
        render_template(
            "dashboard.html",
            username=username,
            api_keys=api_keys,
            message=message,
            allowed_playbooks=ALLOWED_PLAYBOOKS.keys(),  # pass playbooks for dashboard form
        )
    )


@app.route("/run_playbook", methods=["POST"])
@jwt_protected
def run_playbook_dashboard():
    """
    Lets logged-in users run an allowed Ansible playbook from the dashboard.
    """
    playbook_key = request.form.get("playbook")
    extra_vars_raw = request.form.get("extra_vars") or "{}"
    username = g.jwt_payload.get("username", "unknown")

    # parse extra_vars JSON safely
    try:
        extra_vars = json.loads(extra_vars_raw)
    except Exception:
        extra_vars = {}

    if playbook_key not in ALLOWED_PLAYBOOKS:
        return redirect(url_for("dashboard", message="Playbook not allowed"))

    playbook_file = ALLOWED_PLAYBOOKS[playbook_key]

    # Run Ansible playbook on remote control node
    result = run_remote_ansible_playbook(playbook_file, extra_vars, user=username)

    message = f"Playbook '{playbook_key}' finished with status {result['status']}, rc={result['rc']}"
    return redirect(url_for("dashboard", message=message))


@app.route("/logout")
def logout():
    """Logout endpoint - clears JWT cookie and redirects to home"""
    resp = make_response(redirect(url_for("index")))
    resp.set_cookie("jwt", "", expires=0)
    return resp


@app.route("/chpasswd", methods=["POST"])
@jwt_protected
def chpasswd():
    """
    Updates a user password
    """

    new_password = hash_key(request.form["password"])
    current_user = g.jwt_payload.get("username")

    user_db[current_user]["password"] = new_password
    resp = make_response(redirect(url_for("dashboard", message="password updated")))
    return resp


@app.route("/api/newkey", methods=["POST"])
@jwt_protected
def api_new_key():
    """
    Updates a user password
    """
    api_key = secrets.token_urlsafe(32)
    api_hash = hash_key(api_key)
    current_user = g.jwt_payload.get("username")

    user_db[current_user]["api_key"].append(api_hash)
    resp = make_response(
        redirect(url_for("dashboard", message=f"API Key Created {api_key}"))
    )
    return resp


@app.route("/api/deletekey", methods=["POST"])
@jwt_protected
def api_delete_key():
    """
    Deletes an API key
    """
    key_hash = request.form.get("api_key")
    current_user = g.jwt_payload.get("username")

    if key_hash in user_db[current_user]["api_key"]:
        user_db[current_user]["api_key"].remove(key_hash)
        message = "API key deleted successfully"
    else:
        message = "API key not found"

    resp = make_response(redirect(url_for("dashboard", message=message)))
    return resp


@app.route("/<resource>", methods=["GET"])
@api_protected
def get_all(resource):
    """
    Get all entries for a resource.

    Example:
      curl -i \
        -H "Username: alice" \
        -H "Authorization: Bearer secretapikey1" \
        http://localhost:8000/interfaces
    """
    if resource not in data:
        return jsonify({"error": "not found"}), 404
    return jsonify(data[resource])


@app.route("/<resource>", methods=["POST"])
@api_protected
def create(resource):
    """
    Create a new entry in a resource (requires JSON body with 'id').

    Example:
      curl -i -X POST \
        -H "Content-Type: application/json" \
        -H "Username: alice" \
        -H "Authorization: Bearer secretapikey1" \
        -d '{"id":"test1","value":"hello"}' \
        http://localhost:8000/notes
    """
    body = request.json
    if not body or "id" not in body:
        return jsonify({"error": "id required"}), 400

    data.setdefault(resource, {})
    data[resource][body["id"]] = body
    return jsonify(body), 201


@app.route("/<resource>/<id>", methods=["PUT"])
@api_protected
def update(resource, id):
    """
    Update an existing entry by id.

    Example:
      curl -i -X PUT \
        -H "Content-Type: application/json" \
        -H "Username: alice" \
        -H "Authorization: Bearer secretapikey1" \
        -d '{"value":"updated"}' \
        http://localhost:8000/notes/test1
    """
    if resource not in data or id not in data[resource]:
        return jsonify({"error": "not found"}), 404

    data[resource][id].update(request.json)
    return jsonify(data[resource][id])


@app.route("/<resource>/<id>", methods=["DELETE"])
@api_protected
def delete(resource, id):
    """
    Delete an entry by id.

    Example:
      curl -i -X DELETE \
        -H "Username: alice" \
        -H "Authorization: Bearer secretapikey1" \
        http://localhost:8000/notes/test1
    """
    if resource not in data or id not in data[resource]:
        return jsonify({"error": "not found"}), 404

    del data[resource][id]
    return "", 204


@app.route("/search")
@api_protected
def search():
    """
    Search across all resources for a term.

    Example:
      curl -i \
        -H "Username: alice" \
        -H "Authorization: Bearer secretapikey1" \
        "http://localhost:8000/search?q=ipv4"
    """
    q = request.args.get("q", "").lower()
    results = []

    for res, items in data.items():
        for k, v in items.items():
            blob = str(k).lower() + str(v).lower()
            if q in blob:
                results.append({res: {k: v}})

    return jsonify(results)


@app.route("/metrics")
def metrics():
    """
    Prometheus metrics endpoint.
    Returns metrics in Prometheus exposition format.
    """
    return generate_latest(REGISTRY), 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/api/metrics/summary")
@jwt_protected
def metrics_summary():
    """
    Get a summary of Ansible job metrics for the dashboard.
    Returns JSON with metric values.
    """
    # Get current running jobs
    running_jobs = ANSIBLE_JOBS_RUNNING._value._value

    # Get total jobs by collecting samples
    total_jobs = {}
    for sample in ANSIBLE_JOBS_TOTAL.collect()[0].samples:
        # Skip the "_created" timestamp samples, only process "_total" count samples
        if "_created" in sample.name or not sample.name.endswith("_total"):
            continue

        playbook = sample.labels.get("playbook", "unknown")
        status = sample.labels.get("status", "unknown")
        user = sample.labels.get("user", "unknown")
        count = sample.value

        key = f"{playbook}_{status}_{user}"
        total_jobs[key] = {
            "playbook": playbook,
            "status": status,
            "user": user,
            "count": int(count),
        }

    return make_response(
        jsonify(
            {
                "running_jobs": running_jobs,
                "total_jobs": list(total_jobs.values()),
            }
        )
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8000)
