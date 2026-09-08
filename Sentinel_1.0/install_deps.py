import sys
import subprocess
import os

def install_dependencies():
    if sys.version_info < (3, 10):
        print("/!\ Python >= 3.10 requis.")
        sys.exit(1)

    req_file = "requirements.txt"
    if not os.path.exists(req_file):
        print(f"✕ {req_file} introuvable.")
        sys.exit(1)

    print("Installation des dépendances")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "-r", req_file])
    print("✓ Dépendances installées avec succès.")

if __name__ == "__main__":
    install_dependencies()