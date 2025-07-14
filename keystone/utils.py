import paramiko
import os
import subprocess
import requests
from config import *
import mysql.connector
from mysql.connector import errorcode
import subprocess

def get_db_connection():
    try:
        return mysql.connector.connect(
            host=DB_CONFIG['host'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            database=DB_CONFIG['database'],
            port=DB_CONFIG.get('port', 3306),
            connect_timeout=5
        )
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Invalid credentials")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("Database doesn't exist")
        else:
            print(f"Connection error: {err}")
        return None

def format_seconds(value):
    try:
        seconds = int(value)
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        seconds = seconds % 60
        return f"{hours}h {minutes}m {seconds}s"
    except:
        return value


def authenticate_user(username, password):
    admin_auth_url = f"{OS_AUTH_URL}/auth/tokens"
    admin_auth_data = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": OS_USERNAME,
                        "domain": {"name": OS_USER_DOMAIN_NAME},
                        "password": OS_PASSWORD
                    }
                }
            },
            "scope": {
                "project": {
                    "name": OS_PROJECT_NAME,
                    "domain": {"name": OS_PROJECT_DOMAIN_NAME}
                }
            }
        }
    }

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    try:
        # Step 1: Admin authentication to get admin token
        admin_response = requests.post(admin_auth_url, json=admin_auth_data, headers=headers)
        if admin_response.status_code != 201:
            print(f"Debug: Admin authentication failed - {admin_response.status_code}")
            return False, None, None, None, None, "Admin authentication failed"

        admin_token = admin_response.headers.get('X-Subject-Token')

        # Step 2: Fetch users and check if username exists
        users_url = f"{OS_AUTH_URL}/users"
        admin_headers = {
            "X-Auth-Token": admin_token,
            "Accept": "application/json"
        }
        users_response = requests.get(users_url, headers=admin_headers)
        if users_response.status_code != 200:
            print(f"Debug: Error fetching user list - {users_response.status_code}")
            return False, None, None, None, None, "Error fetching user list"

        users = users_response.json().get('users', [])
        user_exists = any(user['name'] == username for user in users)
        if not user_exists:
            return False, None, None, None, None, "User not found"

        # Step 3: Try authenticating with provided username & password
        user_auth_data = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": username,
                            "domain": {"name": OS_USER_DOMAIN_NAME},
                            "password": password
                        }
                    }
                },
                "scope": {
                    "project": {
                        "name": OS_PROJECT_NAME,
                        "domain": {"name": OS_PROJECT_DOMAIN_NAME}
                    }
                }
            }
        }

        user_response = requests.post(admin_auth_url, json=user_auth_data, headers=headers)
        if user_response.status_code == 201:
            token = user_response.headers.get('X-Subject-Token')
            user_id = user_response.json().get('token', {}).get('user', {}).get('id', '')
            role = get_user_role(token, user_id)
            return True, token, role, username, user_id, None

        elif user_response.status_code == 401:
            return False, None, None, None, None, "Incorrect password"

        else:
            return False, None, None, None, None, "Authentication failed"

    except Exception as e:
        print(f"Debug: Exception during authentication - {str(e)}")
        return False, None, None, None, None, "An error occurred during authentication"


def get_user_role(token, user_id):
    # Fetch role assignments for the user
    role_assignments_url = f"{OS_AUTH_URL}/role_assignments?user.id={user_id}"
    headers = {
        "X-Auth-Token": token,
        "Accept": "application/json"
    }
    response = requests.get(role_assignments_url, headers=headers)
    if response.status_code == 200:
        role_assignments = response.json().get('role_assignments', [])
        print(f"Debug: Role assignments for user: {role_assignments}")  # Debugging: Print role assignments

        # Extract role IDs from the assignments
        role_ids = set()
        for assignment in role_assignments:
            role_id = assignment.get('role', {}).get('id', '')
            if role_id:
                role_ids.add(role_id)

        print(f"Debug: Role IDs for user: {role_ids}")  # Debugging: Print role IDs

        # Fetch role names using role IDs
        for role_id in role_ids:
            role_url = f"{OS_AUTH_URL}/roles/{role_id}"
            role_response = requests.get(role_url, headers=headers)
            if role_response.status_code == 200:
                role_name = role_response.json().get('role', {}).get('name', '').lower()
                print(f"Debug: Role ID '{role_id}' has name '{role_name}'")  # Debugging: Print role name
                if role_name == 'admin':
                    return 'admin'
    return 'user'


def get_project_name(token):
    try:
        headers = {"X-Auth-Token": token}
        response = requests.get(f"{OS_AUTH_URL}/auth/projects", headers=headers)
        if response.status_code == 200:
            projects = response.json().get('projects', [])
            if projects:
                return projects[0].get('name', 'N/A')
        return "N/A"
    except Exception as e:
        print(f"Error getting project name: {e}")
        return "Unknown"


def is_keystone_online():
    try:
        response = requests.get(OS_AUTH_URL, timeout=3)
        return response.status_code == 200
    except requests.RequestException:
        return False


#def run_remote_command(command):
#    try:
#        # prepend 'sudo' like before
#        full_command = f"sudo {command}"
#        result = subprocess.run(full_command, shell=True, capture_output=True, text=True)
#        output = result.stdout.strip()
#        error = result.stderr.strip()
#        return output, error
#    except Exception as e:
#        return "", str(e)


def run_remote_command(command):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect('192.168.0.168', username='idmui', password='idmui')
        stdin, stdout, stderr = ssh.exec_command(f"sudo {command}")
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        ssh.close()
        return output, error
    except Exception as e:
        return "", str(e)

def get_admin_token():
    url = f"{OS_AUTH_URL}/auth/tokens"
    headers = {'Content-Type': 'application/json'}

    payload = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": OS_USERNAME,
                        "domain": {"name": OS_USER_DOMAIN_NAME},
                        "password": OS_PASSWORD
                    }
                }
            },
            "scope": {
                "project": {
                    "name": OS_PROJECT_NAME,
                    "domain": {"name": OS_PROJECT_DOMAIN_NAME}
                }
            }
        }
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        return response.headers.get('X-Subject-Token')
    except requests.RequestException as e:
        print(f"[ERROR] Admin token request failed: {e}")
        return None

def get_keystone_headers(token):
    """ Returns the headers for Keystone API calls, including the auth token """
    return {
        "Content-Type": "application/json",
        "X-Auth-Token": token
    }

def get_users(token):
    try:
        headers = {"Content-Type": "application/json", "X-Auth-Token": token}
        url = f"{OS_AUTH_URL}/users"
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            users = resp.json().get('users', [])
            print(f"Fetched {len(users)} users")
            return users
        else:
            print(f"Error fetching users: {resp.status_code} - {resp.text}")
            return []
    except Exception as e:
        print(f"Exception in get_users: {e}")
        return []

def get_user_roles(token, user_id):
    role_assignments_url = f"{OS_AUTH_URL}/role_assignments?user.id={user_id}"
    headers = {"X-Auth-Token": token}
    response = requests.get(role_assignments_url, headers=headers)

    roles = []
    if response.status_code == 200:
        for assignment in response.json().get('role_assignments', []):
            role_id = assignment.get('role', {}).get('id')
            if role_id:
                role_info = requests.get(f"{OS_AUTH_URL}/roles/{role_id}", headers=headers)
                if role_info.status_code == 200:
                    role_name = role_info.json().get('role', {}).get('name', '')
                    roles.append(role_name)
    return list(set(roles))

def get_user_projects(token, user_id):
    headers = {"X-Auth-Token": token}
    response = requests.get(f"{OS_AUTH_URL}/users/{user_id}/projects", headers=headers)
    if response.status_code == 200:
        return [proj['name'] for proj in response.json().get('projects', [])]
    return []
    
def get_projects(token):
    try:
        headers = {"Content-Type": "application/json", "X-Auth-Token": token}
        url = f"{OS_AUTH_URL}/projects"
        resp = requests.get(url, headers=headers)
        return resp.json().get('projects', []) if resp.status_code == 200 else []
    except Exception as e:
        print(f"Error getting projects: {e}")
        return []

def get_user_projects(token, user_id):
    headers = {"X-Auth-Token": token}
    response = requests.get(f"{OS_AUTH_URL}/users/{user_id}/projects", headers=headers)
    if response.status_code == 200:
        return [proj['name'] for proj in response.json().get('projects', [])]
    return []

def get_roles(token):
    try:
        headers = {"Content-Type": "application/json", "X-Auth-Token": token}
        url = f"{OS_AUTH_URL}/roles"
        resp = requests.get(url, headers=headers)
        return resp.json().get('roles', []) if resp.status_code == 200 else []
    except Exception as e:
        print(f"Error getting roles: {e}")
        return []

def map_user_roles(token):
    """Returns a dictionary mapping user_id to their roles in projects."""
    try:
        assignments = get_user_role_assignments(token)
        projects = {p['id']: p['name'] for p in get_projects(token)}
        roles = {r['id']: r['name'] for r in get_roles(token)}
        user_roles = {}

        for assignment in assignments:
            user = assignment.get('user', {}).get('id')
            project = assignment.get('scope', {}).get('project', {}).get('id')
            role = assignment.get('role', {}).get('id')

            if user and project and role:
                project_name = projects.get(project, 'Unknown Project')
                role_name = roles.get(role, 'Unknown Role')
                if user not in user_roles:
                    user_roles[user] = {}
                user_roles[user][project_name] = role_name

        return user_roles

    except Exception as e:
        print(f"Error mapping user roles: {e}")
        return {}


def get_user_role_assignments(token):
    try:
        headers = {"Content-Type": "application/json", "X-Auth-Token": token}
        url = f"{OS_AUTH_URL}/role_assignments?include_names=true"
        resp = requests.get(url, headers=headers)
        return resp.json().get('role_assignments', []) if resp.status_code == 200 else []
    except Exception as e:
        print(f"Error getting role assignments: {e}")
        return []

def create_user(token, username, password, project_id):
    try:
        headers = {"Content-Type": "application/json", "X-Auth-Token": token}
        url = f"{OS_AUTH_URL}/users"
        payload = {"user": {"name": username, "password": password, "default_project_id": project_id, "enabled": True}}
        resp = requests.post(url, json=payload, headers=headers)
        if resp.status_code == 201:
            return True, resp.json().get('user', {})
        else:
            return False, resp.json()
    except Exception as e:
        print(f"Error creating user: {e}")
        return False, {"error": str(e)}


def assign_role(token, user_id, project_id, role_id):
    try:
        headers = {"X-Auth-Token": token}
        url = f"{OS_AUTH_URL}/projects/{project_id}/users/{user_id}/roles/{role_id}"
        resp = requests.put(url, headers=headers)
        return resp.status_code == 204
    except Exception as e:
        print(f"Error assigning role: {e}")
        return False

def delete_user(token, user_id):
    try:
        headers = {"X-Auth-Token": token}
        url = f"{OS_AUTH_URL}/users/{user_id}"
        resp = requests.delete(url, headers=headers)
        return resp.status_code == 204
    except Exception as e:
        print(f"Error deleting user: {e}")
        return False


#endpoint management functions and service management functions

def get_all_endpoints(token):
    try:
        headers = {"X-Auth-Token": token}
        response = requests.get(f"{OS_AUTH_URL}/endpoints", headers=headers)
        if response.status_code == 200:
            return response.json().get("endpoints", [])
    except Exception as e:
        print(f"Error getting endpoints: {e}")
    return []

def create_endpoint(token, interface, url, region, service_id):
    try:
        headers = {"X-Auth-Token": token, "Content-Type": "application/json"}
        data = {
            "endpoint": {
                "interface": interface,
                "url": url,
                "region": region,
                "service_id": service_id,
                "enabled": True
            }
        }
        response = requests.post(f"{OS_AUTH_URL}/endpoints", headers=headers, json=data)
        return response.status_code == 201
    except Exception as e:
        print(f"Error creating endpoint: {e}")
    return False

def delete_endpoint(token, endpoint_id):
    try:
        headers = {"X-Auth-Token": token}
        response = requests.delete(f"{OS_AUTH_URL}/endpoints/{endpoint_id}", headers=headers)
        return response.status_code == 204
    except Exception as e:
        print(f"Error deleting endpoint: {e}")
    return False

def get_all_services(token):
    headers = {'X-Auth-Token': token}
    response = requests.get(f"{OS_AUTH_URL}/services", headers=headers)
    if response.status_code == 200:
        return response.json().get('services', [])
    return []

def create_service(token, name, service_type, description=""):
    headers = {'X-Auth-Token': token, 'Content-Type': 'application/json'}
    data = {
        "service": {
            "name": name,
            "type": service_type,
            "description": description
        }
    }
    response = requests.post(f"{OS_AUTH_URL}/services", headers=headers, json=data)
    return response.status_code == 201

#manage groups  functions
def get_all_groups(token):
    try:
        headers = {"X-Auth-Token": token}
        response = requests.get(f"{OS_AUTH_URL}/groups", headers=headers)
        if response.status_code == 200:
            return response.json().get("groups", [])
    except Exception as e:
        print(f"Error getting groups: {e}")
    return []


def create_group(token, name, description=""):
    try:
        headers = {"X-Auth-Token": token, "Content-Type": "application/json"}
        data = {
            "group": {
                "name": name,
                "description": description,
                "domain_id": "default"
            }
        }
        response = requests.post(f"{OS_AUTH_URL}/groups", headers=headers, json=data)
        return response.status_code == 201
    except Exception as e:
        print(f"Error creating group: {e}")
        return False

def delete_group_by_id(token, group_id):
    try:
        headers = {"X-Auth-Token": token}
        response = requests.delete(f"{OS_AUTH_URL}/groups/{group_id}", headers=headers)
        return response.status_code == 204
    except Exception as e:
        print(f"Error deleting group: {e}")
        return False

def get_all_domains(token):
    try:
        headers = {'X-Auth-Token': token}
        response = requests.get(f"{OS_AUTH_URL}/domains", headers=headers)
        if response.status_code == 200:
            return response.json().get("domains", [])
    except Exception as e:
        print(f"Error getting domains: {e}")
    return []

# Create a new domain
def create_domain(token, name, description="", enabled=True):
    try:
        headers = {'X-Auth-Token': token, 'Content-Type': 'application/json'}
        data = {
            "domain": {
                "name": name,
                "description": description,
                "enabled": enabled
            }
        }
        response = requests.post(f"{OS_AUTH_URL}/domains", headers=headers, json=data)
        return response.status_code == 201
    except Exception as e:
        print(f"Error creating domain: {e}")
        return False

# Delete a domain
def delete_domain(token, domain_id):
    try:
        headers = {'X-Auth-Token': token}
        response = requests.delete(f"{OS_AUTH_URL}/domains/{domain_id}", headers=headers)
        return response.status_code == 204
    except Exception as e:
        print(f"Error deleting domain: {e}")
        return False

def update_domain(token, domain_id, name=None, description=None, enabled=None):
    try:
        headers = {"X-Auth-Token": token, "Content-Type": "application/json"}
        data = {"domain": {}}
        if name is not None:
            data["domain"]["name"] = name
        if description is not None:
            data["domain"]["description"] = description
        if enabled is not None:
            data["domain"]["enabled"] = enabled

        response = requests.patch(f"{OS_AUTH_URL}/domains/{domain_id}", headers=headers, json=data)
        return response.status_code == 200
    except Exception as e:
        print(f"Error updating domain: {e}")
        return False
def get_domain_by_id(token, domain_id):
    try:
        headers = {"X-Auth-Token": token}
        response = requests.get(f"{OS_AUTH_URL}/domains/{domain_id}", headers=headers)
        if response.status_code == 200:
            return response.json().get("domain")
    except Exception as e:
        print(f"Error getting domain by ID: {e}")
    return None

#token management functions
def issue_token():
    """Issue a new token using password authentication"""
    auth_data = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": OS_USERNAME,
                        "domain": {"name": OS_USER_DOMAIN_NAME},
                        "password": OS_PASSWORD
                    }
                }
            },
            "scope": {
                "project": {
                    "name": OS_PROJECT_NAME,
                    "domain": {"name": OS_PROJECT_DOMAIN_NAME}
                }
            }
        }
    }

    headers = {"Content-Type": "application/json"}
    response = requests.post(f"{OS_AUTH_URL}/auth/tokens", headers=headers, json=auth_data)

    if response.status_code == 201:
        token = response.headers["X-Subject-Token"]
        token_info = response.json().get("token", {})
        return token, token_info
    else:
        print("Error issuing token:", response.text)
        return None, None

def get_token_details(token):
    try:
        headers = {
            "X-Auth-Token": token,
            "X-Subject-Token": token
        }
        response = requests.get(f"{OS_AUTH_URL}/auth/tokens", headers=headers)
        if response.status_code == 200:
            data = response.json().get("token", {})
            return {
                "issued_at": data.get("issued_at"),
                "expires_at": data.get("expires_at"),
                "user": data.get("user", {}).get("name"),
                "user_id": data.get("user", {}).get("id"),
                "project": data.get("project", {}).get("name") if data.get("project") else None,
                "roles": [role.get("name") for role in data.get("roles", [])],
            }
    except Exception as e:
        print("Error getting token details:", e)
    return None


def revoke_token(token):
    """Revoke a given token (if revocation is enabled)"""
    headers = {
        "X-Auth-Token": token,
        "X-Subject-Token": token
    }
    response = requests.delete(f"{OS_AUTH_URL}/auth/tokens", headers=headers)
    return response.status_code == 204

#project management functions
def get_all_projects(token):
    url = f"{OS_AUTH_URL}/projects"
    headers = {
        "X-Auth-Token": token,
        "Content-Type": "application/json"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get("projects", [])
    else:
        print("Error fetching projects:", response.text)
        return []

def create_project(token, project_name, description=""):
    url = f"{OS_AUTH_URL}/projects"
    headers = {
        "X-Auth-Token": token,
        "Content-Type": "application/json"
    }
    data = {
        "project": {
            "name": project_name,
            "description": description,
            "enabled": True
        }
    }
    response = requests.post(url, json=data, headers=headers)
    return response.status_code == 201

def delete_project(token, project_id):
    url = f"{OS_AUTH_URL}/projects/{project_id}"
    headers = {
        "X-Auth-Token": token
    }
    response = requests.delete(url, headers=headers)
    return response.status_code == 204
