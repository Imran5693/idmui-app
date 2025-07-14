# IDMUI – Identity Management UI for OpenStack Keystone

A Dockerized Flask-based web interface for managing OpenStack Keystone services, users, roles, endpoints, domains, and projects.

## 📦 Features

- User Authentication (via Keystone)
- CRUD for:
  - Users
  - Projects (Tenants)
  - Roles
  - Domains
  - Endpoints
  - Services
- Real-time Keystone service status check
- Remote Keystone management via SSH (Paramiko)
- Responsive Web UI using HTML/CSS/Bootstrap
- Compatible with Ubuntu VM & Docker

---

## 🧰 Requirements

- Python 3.11+ (already in Docker image)
- Docker (on host VM or local system)
- OpenStack Keystone running on the **same VM** or accessible via IP
- Valid `config.py` with Keystone admin credentials

---

## 🚀 Getting Started (on your VM)

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Imran5693/idmui-app.git
   cd idmui-app

  2. **Update Configuration**:
Edit config.py to update the OpenStack Keystone URL:

OS_AUTH_URL = "http://<your-vm-ip>:5000/v3"
Replace <your-vm-ip> with your VM's actual IP address.

If your application uses SSH (via Paramiko) for remote Keystone service control, update the IP in keystone/utils.py:
```bash
ssh.connect('<your-vm-ip>', username='idmui', password='idmui')

3.  **Build the Docker Image**:
```bash
docker build -t idmui-app .

4. **Run the Docker Container**:
```bash
docker run -d --name idmui-container -p 8000:8000 idmui-app
5. **Access the Application**:
Open your browser and navigate to:
http://<your-vm-ip>:8000
