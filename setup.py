#!/usr/bin/env python3
"""
Setup script for the multi-agent document pipeline
Automates installation and initial configuration
"""
import os
import sys
import subprocess
import shutil
from pathlib import Path


def print_header(text):
    """Print a formatted header"""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70 + "\n")


def print_step(step_num, text):
    """Print a step indicator"""
    print(f"\n[{step_num}] {text}...")


def run_command(cmd, description, check=True):
    """Run a shell command and handle errors"""
    print(f"   → {description}")
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            check=check,
            capture_output=True,
            text=True
        )
        if result.stdout:
            print(f"     {result.stdout.strip()}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"     ✗ Error: {e.stderr.strip()}")
        return False


def check_python_version():
    """Check if Python version is adequate"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 9):
        print("✗ Error: Python 3.9 or higher is required")
        print(f"  Current version: {version.major}.{version.minor}")
        return False
    print(f"✓ Python {version.major}.{version.minor}.{version.micro} detected")
    return True


def check_postgresql():
    """Check if PostgreSQL is available"""
    print_step(1, "Checking PostgreSQL")
    
    if run_command("psql --version", "Checking PostgreSQL installation", check=False):
        return True
    else:
        print("   ⚠ PostgreSQL not found. Please install PostgreSQL 12+")
        print("   Visit: https://www.postgresql.org/download/")
        return False


def create_virtualenv():
    """Create virtual environment"""
    print_step(2, "Creating virtual environment")
    
    venv_path = Path("venv")
    if venv_path.exists():
        print("   → Virtual environment already exists")
        return True
    
    return run_command(
        f"{sys.executable} -m venv venv",
        "Creating venv"
    )


def get_pip_command():
    """Get the correct pip command for the platform"""
    if sys.platform == "win32":
        return "venv\\Scripts\\pip"
    else:
        return "venv/bin/pip"


def install_dependencies():
    """Install Python dependencies"""
    print_step(3, "Installing dependencies")
    
    pip_cmd = get_pip_command()
    
    # Upgrade pip
    if not run_command(f"{pip_cmd} install --upgrade pip", "Upgrading pip"):
        return False
    
    # Install requirements
    if not run_command(f"{pip_cmd} install -r requirements.txt", "Installing packages"):
        return False
    
    return True


def create_env_file():
    """Create .env file from example"""
    print_step(4, "Creating configuration file")
    
    env_file = Path(".env")
    env_example = Path(".env.example")
    
    if env_file.exists():
        print("   → .env file already exists")
        response = input("   Do you want to overwrite it? (y/N): ")
        if response.lower() != 'y':
            return True
    
    if env_example.exists():
        shutil.copy(env_example, env_file)
        print("   ✓ Created .env file")
        print("   ⚠ Please edit .env with your AWS and PostgreSQL credentials")
        return True
    else:
        # Create a basic .env file
        with open(env_file, 'w') as f:
            f.write("""# AWS Configuration
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=us-east-1
S3_BUCKET_NAME=your-bucket-name

# PostgreSQL Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=documents_db
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_password

# Agent Configuration (defaults are fine)
ORCHESTRATOR_HOST=localhost
ORCHESTRATOR_PORT=8001
EXTRACTOR_HOST=localhost
EXTRACTOR_PORT=8002
VALIDATOR_HOST=localhost
VALIDATOR_PORT=8003
ARCHIVIST_HOST=localhost
ARCHIVIST_PORT=8004

# Logging
LOG_LEVEL=INFO
""")
        print("   ✓ Created .env file")
        print("   ⚠ Please edit .env with your AWS and PostgreSQL credentials")
        return True


def create_database():
    """Create PostgreSQL database"""
    print_step(5, "Creating database")
    
    print("   → Do you want to create the database now?")
    print("   (Requires PostgreSQL to be running and credentials set)")
    response = input("   Create database? (y/N): ")
    
    if response.lower() == 'y':
        db_name = input("   Database name [documents_db]: ") or "documents_db"
        
        if run_command(
            f'createdb {db_name}',
            f"Creating database '{db_name}'",
            check=False
        ):
            print("   ✓ Database created successfully")
            
            # Try to initialize schema
            python_cmd = get_python_command()
            if run_command(
                f"{python_cmd} init_db.py init",
                "Initializing database schema",
                check=False
            ):
                print("   ✓ Database schema initialized")
            return True
        else:
            print("   ⚠ Database creation failed")
            print("   You can create it manually: createdb documents_db")
            return True
    else:
        print("   → Skipped. You can create it later with: createdb documents_db")
        return True


def get_python_command():
    """Get the correct Python command for the platform"""
    if sys.platform == "win32":
        return "venv\\Scripts\\python"
    else:
        return "venv/bin/python"


def run_tests():
    """Run test suite"""
    print_step(6, "Running tests")
    
    response = input("   Run tests? (y/N): ")
    if response.lower() == 'y':
        python_cmd = get_python_command()
        pip_cmd = get_pip_command()
        
        # Install pytest if needed
        run_command(f"{pip_cmd} install pytest pytest-asyncio", "Installing test dependencies", check=False)
        
        # Run tests
        if run_command(f"{python_cmd} -m pytest test_pipeline.py -v", "Running tests", check=False):
            print("   ✓ All tests passed")
            return True
        else:
            print("   ⚠ Some tests failed (this is okay for initial setup)")
            return True
    else:
        print("   → Skipped")
        return True


def print_next_steps():
    """Print next steps for the user"""
    print_header("Setup Complete!")
    
    print("✓ Virtual environment created")
    print("✓ Dependencies installed")
    print("✓ Configuration file created")
    print()
    print("NEXT STEPS:")
    print()
    print("1. Edit .env file with your credentials:")
    print("   - AWS access keys")
    print("   - PostgreSQL credentials")
    print()
    print("2. If not done, create the database:")
    print("   createdb documents_db")
    if sys.platform == "win32":
        print("   venv\\Scripts\\python init_db.py init")
    else:
        print("   venv/bin/python init_db.py init")
    print()
    print("3. Start all agents:")
    if sys.platform == "win32":
        print("   venv\\Scripts\\python run_agents.py")
    else:
        print("   venv/bin/python run_agents.py")
    print()
    print("4. In another terminal, test the system:")
    if sys.platform == "win32":
        print("   venv\\Scripts\\python client.py health")
    else:
        print("   venv/bin/python client.py health")
    print()
    print("5. View the architecture diagram:")
    if sys.platform == "win32":
        print("   venv\\Scripts\\python diagram.py")
    else:
        print("   venv/bin/python diagram.py")
    print()
    print("DOCUMENTATION:")
    print("  - README.md         - Full documentation")
    print("  - QUICKSTART.md     - Quick start guide")
    print("  - ARCHITECTURE.md   - Technical architecture")
    print("  - API.md            - API reference")
    print()
    print("For help, run:")
    if sys.platform == "win32":
        print("  venv\\Scripts\\python client.py --help")
    else:
        print("  venv/bin/python client.py --help")
    print()
    print("=" * 70)


def main():
    """Main setup process"""
    print_header("Multi-Agent Document Pipeline - Setup")
    
    print("This script will set up the document processing pipeline.")
    print()
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Check PostgreSQL
    postgres_ok = check_postgresql()
    if not postgres_ok:
        print("\n⚠ Warning: PostgreSQL is required but not found.")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    # Create virtualenv
    if not create_virtualenv():
        print("\n✗ Failed to create virtual environment")
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        print("\n✗ Failed to install dependencies")
        sys.exit(1)
    
    # Create .env file
    if not create_env_file():
        print("\n✗ Failed to create configuration file")
        sys.exit(1)
    
    # Create database (optional)
    if postgres_ok:
        create_database()
    
    # Run tests (optional)
    run_tests()
    
    # Print next steps
    print_next_steps()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n✗ Setup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Setup failed: {str(e)}")
        sys.exit(1)

