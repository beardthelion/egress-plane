# Live typosquat scan

A real scan over PyPI packages that look like high-value targets
(`os_sys`, `pip_install`, `discord_py`, `crypto`, `jwt_auth`, and a
dozen more lookalike names), run with the released `egress-plane`.
No reconstruction: these packages are live on PyPI today and each was
scanned exactly as downloaded.

## What the scan found

16 lookalike packages downloaded and scanned. Most are what they look
like: repackaged or legitimate-but-poorly-named libraries. One is the
shape a supply-chain payload takes.

### `os-sys` 2.1.4, live on PyPI

```sh
pip download os-sys --no-deps -d sq/
unzip sq/os_sys-2.1.4-py3-none-any.whl -d sq/os_sys
egress-plane scan sq/os_sys
```

The report flags egress destinations no package in this name space
has any business reaching:

```
__main__.py:546    python:requests.get -> https://stranica.nl/server-dist/py_install.py_install_zip
__main__.py:551    python:requests.get -> https://stranica.nl/server-dist/server.info
__main__.py:556    python:requests.get -> https://stranica.nl/server-dist/server.py_install
commands/__init__.py:46   python:requests.get -> https://b24-rejckj.bitrix24.com/disk/downloadFile/42/?&ncc=1&filename=setup.py
module.py:415    python:socket.create_connection -> google.com:80
```

The code behind those sites does what the destinations suggest:

- `__main__.py:543-556` downloads a binary payload
  (`py_install.py_install_zip`), a `server.info`, and
  `server.py_install` from `stranica.nl` and writes them to a
  `server-dist/` directory for use.
- `commands/__init__.py:46` fetches a `setup.py` hosted on a
  Bitrix24 file share, a host no registry reviews, and writes it to
  `test.txt`.
- `commands/` defines a console whose `cmd()` runs
  `subprocess.getstatusoutput(command)`, and line 301 self-updates
  the package with `pip install --upgrade os_sys`.
- `__main__.py:197` dispatches through
  `exec(str(obj) + '.' + str(argument), globals=globals())`.

`os-sys` typosquats `os`/`sys`, ships a junk-drawer of unrelated
repackaged libraries to look substantial, and pulls executable
payloads from off-registry hosts at runtime. This is the documented
supply-chain payload shape: arbitrary code delivered from outside
the package registry, fetched only when the package runs.

## The run on every other candidate

```
pip_install      | complete    | urllib.request.urlretrieve -> https://bootstrap.pypa.io/get-pip.py
                                 subprocess.check_call -> sys.executable
                                 (a disclosed dynamic-pip helper; the
                                  download+execute surface is real but
                                  is the package's documented purpose)
discord_py_api   | incomplete  | aiohttp sessions, TCPConnector
                                 (a repack of discord.py; the aiohttp
                                  calls are the upstream library's)
py_crypto        | incomplete  | requests.get/post/delete to
                                 Constants.* (Binance trading endpoints)
websockets       | incomplete  | os.system in cli.py, socket creation
                                 (the real library's code)
crypto           | complete    | 0 sites
jwt_auth         | complete    | 0 sites
numpy_utils      | complete    | 0 sites
```

## Reading it

`egress-plane` does not decide a package is malicious. It surfaces
every route code takes out and lets the auditor judge intent. What it
removed here was the searching: instead of reading
`os-sys`'s 500 files, the report put `stranica.nl` and a Bitrix24
share on one line each and made the remote-code delivery the first
thing a reviewer sees.

Whether `os-sys` is malice or negligent design is a question the
maintainers answer. What it *could* deliver is what the report shows.
