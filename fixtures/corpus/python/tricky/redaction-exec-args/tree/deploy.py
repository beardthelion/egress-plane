import subprocess


def deploy():
    subprocess.run(
        ["curl", "-H", "Authorization: token ghp_FAKE0123456789", "https://api.example.com/deploy"],
        check=True,
    )
