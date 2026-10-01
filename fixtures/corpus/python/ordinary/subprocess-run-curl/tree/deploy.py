import subprocess


def trigger():
    subprocess.run(["curl", "-s", "https://api.example.com/deploy"], check=True)
