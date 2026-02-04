# Elvik E-Commerce Platform

## Setup Instructions

### Prerequisites
- Python 3.8 or higher installed on your system
- pip (Python package installer)

### Installation Steps

1. **Navigate to the project directory**
```bash
cd security_test
```

2. **Create a virtual environment**
```bash
python -m venv venv
```

3. **Activate the virtual environment**

For Windows PowerShell:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\venv\Scripts\Activate.ps1
```

For Windows Command Prompt:
```cmd
venv\Scripts\activate.bat
```

For macOS/Linux:
```bash
source venv/bin/activate
```

Note: You should see `(venv)` at the start of your command prompt when the virtual environment is activated.

4. **Install required dependencies**
```bash
pip install -r requirements.txt
```

5. **Initialize the database**
```bash
python init_db.py
```

This command will create the SQLite database (`database.db`) with all necessary tables and sample data.

6. **Run the application**
```bash
python myApp.py
```

The application will start running on `http://127.0.0.1:5000/`

7. **Access the application**

Open your web browser and navigate to:
```
http://127.0.0.1:5000/
```

## Default Login Credentials

After initializing the database, you can log in with the following default accounts:

### Admin Account
- **Email**: admin@admin.com
- **Password**: admin123

### Seller Account
- **Email**: sarah@sellers.com
- **Password**: seller123

### Customer Account
- **Email**: turki@gmail.com
- **Password**: Turki123

## Stopping the Application

To stop the application, press `Ctrl+C` in the terminal where the app is running.

## Deactivating the Virtual Environment

When you're done working with the application, you can deactivate the virtual environment:

```bash
deactivate
```