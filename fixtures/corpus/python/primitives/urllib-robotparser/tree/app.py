import urllib.robotparser


def probe():
    return urllib.robotparser.RobotFileParser()
