
from keystone.utils import *

from keystone.utils import authenticate_user
from flask import render_template, session, redirect, url_for, flash, request
from keystone import bp
from keystone.utils import run_remote_command
import requests
from datetime import datetime
from config import OS_AUTH_URL


@bp.route('/')
def index():
    return render_template('login.html', title="Login")

@bp.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # ✅ Include user_id in returned values
    success, token, role, username, user_id, error_message = authenticate_user(username, password)

    if success:
        session['token'] = token
        session['role'] = role
        session['username'] = username
        session['user_id'] = user_id  # ✅ Now this will work

        project_name = get_project_name(token)
        session['project_name'] = project_name

        print(f"Debug: User '{username}' logged in with role '{role}'")  # Debugging
        flash('Login successful!', 'success')

        if role == 'admin':
            return redirect(url_for('keystone.admin_dashboard'))
        else:
            return redirect(url_for('keystone.user_dashboard'))
    else:
        if error_message == "User not found":
            flash('User not found.', 'error')
        elif error_message == "Incorrect password":
            flash('Incorrect password.', 'error')
        else:
            flash('Authentication failed. Please try again.', 'error')
        return redirect(url_for('keystone.index'))


@bp.route('/admin/dashboard')
def admin_dashboard():
    if 'token' not in session or session.get('role') != 'admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('keystone.login'))
    
    username = session.get('username', 'Admin')  # Get username from session
    return render_template('dashboard.html', username=username, role='Admin', project_name=session.get('project_name', 'Unknown'))

@bp.route('/user/dashboard')
def user_dashboard():
    if 'token' not in session or session.get('role') != 'user':
        flash('Unauthorized access', 'error')
        return redirect(url_for('keystone.login'))
    
    username = session.get('username', 'User')  # Get username from session
    return render_template('dashboard.html', username=username, role='User', project_name=session.get('project_name', 'Unknown'))

# ✅ 1. Keystone API Status
@bp.route('/keystone/status')
def keystone_status():
    if 'token' not in session:
        flash('Unauthorized access', 'error')
        return redirect(url_for('keystone.login'))

    try:
        status_url = f"{OS_AUTH_URL}/"
        headers = {"X-Auth-Token": session['token'], "Accept": "application/json"}
        response = requests.get(status_url, headers=headers)

        if response.status_code == 200:
            status_data = {
                'healthy': True,
                'version': response.json().get('version', {}).get('id', 'unknown'),
                'status': 'Operational',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'details': response.json()
            }
        else:
            status_data = {
                'healthy': False,
                'error': f"API returned {response.status_code}",
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
    except Exception as e:
        status_data = {'healthy': False, 'error': str(e), 'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    
    return render_template('keystone_status.html', status=status_data)


# ✅ 2. Remote Service Control (Apache2)
@bp.route('/keystone/manage', methods=['GET', 'POST'])
def keystone_manage():
    if 'token' not in session or session.get('role') != 'admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('keystone.index'))

    status = "unknown"
    if request.method == 'POST':
        action = request.form.get('action')
        if action in ['start', 'stop', 'restart']:
            output, err = run_remote_command(f"systemctl {action} apache2")
            if err:
                flash(f"Failed to {action} Apache2: {err}", 'error')
            else:
                flash(f"Apache2 successfully {action}ed.", 'success')
        else:
            flash('Invalid action.', 'error')

    output, err = run_remote_command("systemctl is-active apache2")
    status = output if not err else "unknown"
    return render_template('keystone_manage.html', status=status)


# ✅ 3. Keystone Service List
@bp.route('/identity-service/service-management')
def service_management():
    if 'token' not in session:
        flash('Unauthorized access', 'error')
        return redirect(url_for('keystone.index'))

    headers = {"X-Auth-Token": session['token'], "Accept": "application/json"}
    try:
        response = requests.get(f"{OS_AUTH_URL}/services", headers=headers)
        services = response.json().get('services', []) if response.status_code == 200 else []
    except Exception as e:
        flash(f'Error fetching services: {str(e)}', 'error')
        services = []
    return render_template('service_management.html', services=services)


# ✅ 4. Identity Sub-Menus (Initial Scaffolds)
@bp.route('/user-management', methods=['GET', 'POST'])
def user_management():
    token = get_admin_token()
    if not token:
        flash("Failed to retrieve Keystone admin token.", "error")
        return redirect(url_for('keystone.admin_dashboard'))

    # Handle new user registration
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        project_id = request.form.get('project_id')
        role_id = request.form.get('role_id')

        created, result = create_user(token, username, password, project_id)
        if created:
            user_id = result.get('id')
            if user_id:
                assign_success = assign_role(token, user_id, project_id, role_id)
                if assign_success:
                    flash("User created and role assigned successfully.", "success")
                else:
                    flash("User created, but failed to assign role.", "error")
            else:
                flash("User created but failed to retrieve user ID.", "error")
        else:
            error_msg = result.get('error', 'Unknown error') if isinstance(result, dict) else str(result)
            flash(f"Failed to create user: {error_msg}", "error")
        return redirect(url_for('keystone.user_management'))

    # Fetch existing data
    users = get_users(token)
    projects = get_projects(token)
    roles = get_roles(token)
    user_role_map = map_user_roles(token)
    role_assignments = get_user_role_assignments(token)
    # Build mappings for name lookups
    project_map = {p['id']: p['name'] for p in projects}
    role_map = {r['id']: r['name'] for r in roles}

    # Map user ID to their assignments
    user_map = {user['id']: user for user in users}
    for user in users:
        user['role_assignments'] = []

    for assignment in role_assignments:
        if 'user' in assignment and 'project' in assignment and 'role' in assignment:
            user_id = assignment['user']['id']
            project_id = assignment['project']['id']
            role_id = assignment['role']['id']

            if user_id in user_map:
                user_map[user_id].setdefault('assignments', []).append({
                    'project': project_map.get(project_id, 'Unknown'),
                    'role': role_map.get(role_id, 'Unknown')
                })

    return render_template(
        'user_management.html',
        users=users,
        projects=projects,
        roles=roles,
        user_assignments=user_role_map
    )

@bp.route('/delete-user/<user_id>', methods=['POST'])
def delete_user_route(user_id):
    token = get_admin_token()
    if not token:
        flash("Failed to retrieve Keystone admin token.", "error")
    else:
        success = delete_user(token, user_id)
        if success:
            flash("User deleted successfully.", "success")
        else:
            flash("Failed to delete user.", "error")
    return redirect(url_for('keystone.user_management'))

@bp.route('/identity-service/project-management')
def project_management():
    return render_template('under_construction.html', title="Project Management")

@bp.route('/identity-service/token-management')
def token_management():
    return render_template('under_construction.html', title="Token Management")

@bp.route('/admin/domains', methods=['GET', 'POST'])
def manage_domains():
    token = get_admin_token()

    if request.method == 'POST':
        name = request.form.get("name")
        description = request.form.get("description")
        enabled = request.form.get("enabled") == "on"
        success = create_domain(token, name, description, enabled)
        flash("Domain created." if success else "Failed to create domain.", "success" if success else "danger")
        return redirect(url_for('keystone.manage_domains'))

    domains = get_all_domains(token)
    return render_template('manage_domain.html', domains=domains)

@bp.route('/admin/domains/delete/<domain_id>', methods=['GET', 'POST'])
def delete_existing_domain(domain_id):
    token = get_admin_token()
    success = delete_domain(token, domain_id)
    flash("Domain deleted." if success else "Failed to delete domain. Domain is active ! ", "success" if success else "danger")
    return redirect(url_for('keystone.manage_domains'))

@bp.route('/admin/domains/toggle/<domain_id>', methods=['POST'])
def toggle_domain_enabled(domain_id):
    token = get_admin_token()
    enabled_str = request.form.get("enabled", "true")
    enabled = enabled_str.lower() == "true"

    success = update_domain(token, domain_id, enabled=enabled)
    if success:
        flash(f"Domain {'enabled' if enabled else 'disabled'} successfully.", "success")
    else:
        flash("Failed to update domain status.", "danger")

    return redirect(url_for('keystone.manage_domains'))


# List all groups
@bp.route('/admin/groups', methods=['GET'])
def list_groups():
    token = get_admin_token()
    groups = get_all_groups(token)
    return render_template('admin/groups.html', groups=groups)

# Create new group
@bp.route('/admin/groups/create', methods=['POST'])
def create_new_group():
    token = get_admin_token()
    name = request.form.get('group_name')
    description = request.form.get('description', '')
    success = create_group(token, name, description)
    if success:
        flash("Group created successfully.", "success")
    else:
        flash("Failed to create group.", "danger")
    return redirect(url_for('keystone.list_groups'))
@bp.route('/admin/groups/delete/<group_id>', methods=['GET'])

def delete_group(group_id):
    token = get_admin_token()
    success = delete_group_by_id(token, group_id)
    if success:
        flash("Group deleted successfully.", "success")
    else:
        flash("Failed to delete group.", "danger")
    return redirect(url_for('keystone.list_groups'))


@bp.route('/identity-service/configuration-management')
def configuration_management():
    return render_template('under_construction.html', title="Configuration Management")

#endpoint management and sarver management
@bp.route('/admin/endpoints', methods=['GET', 'POST'])
def list_endpoints():
    token = get_admin_token()
    endpoints = get_all_endpoints(token)
    services = get_all_services(token)

    # Create a dictionary to map service_id to service info
    service_dict = {s['id']: {'type': s['type'], 'name': s['name']} for s in services}

    return render_template('admin/endpoint.html',
                           endpoints=endpoints,
                           services=services,
                           service_dict=service_dict)


@bp.route('/admin/services')
def manage_services():
    token = get_admin_token()
    services = get_all_services(token)
    return render_template('admin/manage_services.html', services=services)


@bp.route('/admin/services/create', methods=['GET', 'POST'])
def create_service_form():
    if request.method == 'POST':
        token = get_admin_token()
        name = request.form['name']
        service_type = request.form['type']
        description = request.form['description']
        create_service(token, name, service_type, description)
        flash("Service created.", "success")
        return redirect(url_for('keystone.list_endpoints'))
    return render_template('admin/create_service.html')

def delete_service(token, service_id):
    headers = {'X-Auth-Token': token}
    response = requests.delete(f"{OS_AUTH_URL}/services/{service_id}", headers=headers)
    return response.status_code == 204

@bp.route('/admin/services/delete/<service_id>', methods=['POST'])
def delete_service_route(service_id):
    token = get_admin_token()
    success = delete_service(token, service_id)
    flash("Service deleted." if success else "Failed to delete service.", "success" if success else "danger")
    return redirect(url_for('keystone.manage_services'))


@bp.route('/admin/endpoints/create', methods=['POST'])
def create_new_endpoint():
    token = get_admin_token()
    interface = request.form.get('interface')
    url = request.form.get('url')
    region = request.form.get('region')
    service_id = request.form.get('service_id')

    if create_endpoint(token, interface, url, region, service_id):
        flash("Endpoint created successfully.", "success")
    else:
        flash("Failed to create endpoint.", "danger")
    return redirect(url_for('keystone.list_endpoints'))

@bp.route('/admin/endpoints/delete/<endpoint_id>')
def delete_endpoint_route(endpoint_id):
    token = get_admin_token()
    if delete_endpoint(token, endpoint_id):
        flash("Endpoint deleted.", "success")
    else:
        flash("Failed to delete endpoint.", "danger")
    return redirect(url_for('keystone.list_endpoints'))

@bp.route('/admin/token')
def view_token():
    token = get_admin_token()
    token_details = get_token_details(token)
    return render_template('token.html', token=token, token_details=token_details)

@bp.route('/admin/token/revoke', methods=['POST'])
def revoke_admin_token():
    admin_token = get_admin_token()
    success = revoke_token(admin_token, admin_token)
    if success:
        flash("Token revoked successfully.", "success")
    else:
        flash("Failed to revoke token.", "danger")
    return redirect(url_for('keystone.view_token'))

#project management
@bp.route('/admin/projects')
def list_projects():
    token = get_admin_token()
    projects = get_all_projects(token)
    return render_template('projects.html', projects=projects)

@bp.route('/admin/projects/create', methods=['POST'])
def create_new_project():
    project_name = request.form['project_name']
    description = request.form.get('description', '')
    token = get_admin_token()
    success = create_project(token, project_name, description)
    if success:
        flash("Project created successfully.", "success")
    else:
        flash("Failed to create project.", "danger")
    return redirect(url_for('keystone.list_projects'))

@bp.route('/admin/projects/delete/<project_id>', methods=['POST' , 'GET'])
def delete_existing_project(project_id):
    token = get_admin_token()
    success = delete_project(token, project_id)
    if success:
        flash("Project deleted successfully.", "success")
    else:
        flash("Failed to delete project.", "danger")
    return redirect(url_for('keystone.list_projects'))

# ✅ 5. Database Menu Route

@bp.app_template_filter('format_seconds')
def format_seconds_filter(value):
    return format_seconds(value)

# Database Management Routes
@bp.route('/admin/database-management', methods=['GET'])
def database_management():
    if 'token' not in session or session.get('role') != 'admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('keystone.login'))

    connection = get_db_connection()
    if not connection:
        flash('Failed to connect to database', 'error')
        return redirect(url_for('keystone.database_management'))

    try:
        cursor = connection.cursor(dictionary=True)

        # Get database status
        cursor.execute("SHOW STATUS")
        status = {item['Variable_name']: item['Value'] for item in cursor.fetchall()}

        # Get table stats (filter out those with NULL update_time)
        cursor.execute("""
            SELECT 
                table_name, 
                table_rows, 
                ROUND(data_length/1024/1024, 2) AS data_size_mb,
                ROUND(index_length/1024/1024, 2) AS index_size_mb,
                ROUND((data_length + index_length)/1024/1024, 2) AS total_size_mb,
                update_time
            FROM information_schema.tables
            WHERE table_schema = %s AND update_time IS NOT NULL
            ORDER BY total_size_mb DESC
        """, (DB_CONFIG['database'],))
        stats = cursor.fetchall()

        # Extract filtered table names for display
        tables = [table['table_name'] for table in stats]

        # Get running processes
        cursor.execute("SHOW PROCESSLIST")
        processes = cursor.fetchall()

        cursor.close()
        connection.close()

        return render_template('database_management.html',
                               status=status,
                               tables=tables,
                               stats=stats,
                               processes=processes,
                               db_name=DB_CONFIG['database'])
    except Exception as e:
        flash(f'Database error: {str(e)}', 'error')
        if connection:
            connection.close()
        return redirect(url_for('keystone.admin_dashboard'))


@bp.route('/database-management/query', methods=['GET', 'POST'])
def database_query():
    if 'token' not in session or session.get('role') != 'admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('keystone.index'))  # update if 'index' is also under keystone

    if request.method == 'POST':
        query = request.form.get('query')
        if not query:
            flash('No query provided', 'error')
            return redirect(url_for('keystone.database_management'))

        connection = get_db_connection()
        if not connection:
            flash('Failed to connect to database', 'error')
            return redirect(url_for('keystone.database_management'))

        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute(query)

            if query.strip().lower().startswith('select'):
                results = cursor.fetchall()
                columns = list(results[0].keys()) if results else []
                return render_template('query_results.html', 
                                       results=results,
                                       columns=columns,
                                       query=query)
            else:
                affected_rows = cursor.rowcount
                connection.commit()
                flash(f'Query executed successfully. Affected rows: {affected_rows}', 'success')

            cursor.close()
            connection.close()
            return redirect(url_for('keystone.database_management'))
        except Exception as e:
            flash(f'Query error: {str(e)}', 'error')
            if connection:
                connection.close()
            return redirect(url_for('keystone.database_management'))

    return redirect(url_for('keystone.database_management'))

@bp.route('/database-management/backup')
def database_backup():
    if 'token' not in session or session.get('role') != 'admin':
        flash('Unauthorized access', 'error')
        return redirect(url_for('keystone.index'))  # same here

    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = f"/tmp/keystone_backup_{timestamp}.sql"

        subprocess.run([
            'mysqldump',
            '-h', DB_CONFIG['host'],
            '-u', DB_CONFIG['user'],
            f"-p{DB_CONFIG['password']}",
            DB_CONFIG['database'],
            '--result-file', backup_file
        ], check=True)

        flash(f'Database backup created at {backup_file}', 'success')
    except subprocess.CalledProcessError as e:
        flash(f'Backup failed: {str(e)}', 'error')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')

    return redirect(url_for('keystone.database_management'))

# User List
@bp.route('/user/list')
def user_list():
    if 'token' not in session:
        flash("Please login first.", "danger")
        return redirect(url_for('keystone.index'))

    user_token = session['token']
    current_user_id = session.get('user_id')

    users = []
    try:
        # Step 1: get an admin token
        admin_token = get_admin_token()

        # Step 2: list all users with the admin token
        url = f"{OS_AUTH_URL}/users"
        headers = {"X-Auth-Token": admin_token, "Accept": "application/json"}
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()

        all_users = resp.json().get('users', [])
        for u in all_users:
            uid = u['id']
            roles = get_user_roles(admin_token, uid)
            projects = get_user_projects(admin_token, uid)
            users.append({
                'id': uid,
                'name': u.get('name'),
                'roles': roles,
                'projects': projects
            })

    except Exception as e:
        # If admin list fails, show only the current user
        print(f"Failed to fetch all users: {e}")
        flash("Could not retrieve full user list; showing your account only.", "warning")

        # Current user info
        roles = get_user_roles(user_token, current_user_id)
        projects = get_user_projects(user_token, current_user_id)
        users = [{
            'id': current_user_id,
            'name': session.get('username'),
            'roles': roles,
            'projects': projects
        }]

    return render_template('user_list.html', users=users)

@bp.route('/user/projects')
def user_projects():
    if 'token' not in session:
        flash("Please login first.", "danger")
        return redirect(url_for('keystone.index'))

    token = session['token']
    user_id = session.get('user_id')

    projects = get_user_projects(token, user_id)

    project_list = [{'name': proj, 'id': idx, 'domain': 'Default'} for idx, proj in enumerate(projects)]

    return render_template('user_projects.html', projects=project_list)

# User Domains
@bp.route('/user/domains')
def user_domains():
    if 'token' not in session:
        flash("Please login first.", "danger")
        return redirect(url_for('keystone.index'))

    # Hardcoded for now because normal users usually have only "Default" domain
    domains = [{'id': 'default', 'name': 'Default'}]

    return render_template('user_domains.html', domains=domains)