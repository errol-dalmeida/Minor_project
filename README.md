# Python P2P Communication and Native Blockchain DPKI

The current implementation runs entirely in terminals. Each Python peer owns its
keys, DID, local blockchain, trust state, and revocation cache. A TCP relay routes
messages between peers on the same computer or LAN. The Python path does not use
EVM, Hardhat, or the JavaScript libp2p implementation retained in this repository.

Direct messages use ECIES (ECDH plus a symmetric AEAD cipher), with ECDSA signatures.
Channel messages and public broadcasts also require valid sender signatures.
Registration, revocation, reinstatement, and rotation are signed ledger transactions;
chain synchronization checks hashes, proof of work, and transaction signatures.

Start with the [Debian requirements](#debian-lan-guide-requirements-and-device-layout),
follow setup steps 1-7, then run the [LAN tests](#8-run-the-tests-across-the-actual-lan-devices).
The [command reference](#terminal-commands), [automated checks](#automated-verification),
and [troubleshooting table](#troubleshooting-on-debian) are below.

## Debian LAN guide: requirements and device layout

Follow this guide on Debian 12 or 13 with Python 3.11 or newer. Python 3.11+
is required for the supplied regression tests, which use `asyncio.timeout()`.
All commands labelled `bash` run in a Linux terminal. Commands labelled `text`
run **inside the peer CLI**, after its `[ACTIVE] (...) >` prompt appears.

Two devices are enough to test a real LAN connection. Use three peers to test
the scoped revocation and lazy verification scenario. This example puts one
peer on each of three Debian devices:

| Device | Example LAN IPv4 | Processes | Terminals |
| --- | --- | --- | --- |
| A | `192.168.1.100` | Relay + Node 1 (Alice) | Two |
| B | `192.168.1.101` | Node 2 (Bob) | One |
| C | `192.168.1.102` | Node 3 (Charlie) | One |

Replace these example addresses with your devices' actual addresses. A separate
relay-only device also works: point every peer at that device's IPv4 address.

Requirements:

- Devices on a LAN that permits connections between clients, using Ethernet or
  Wi-Fi. A guest Wi-Fi network or AP/client isolation can block these connections.
- The same current Python source files on every device.
- Python 3.11+, `venv`, and `cryptography>=42.0.0`, as declared in
  `p2p-simple/requirements.txt`.
- Administrator access for Debian package installation and any required firewall
  rule. Run the relay and peers as your normal user.
- Internet access for the initial APT/PyPI installation. The running application
  uses LAN TCP connections and does not need an external blockchain or RPC service.
- Inbound TCP `4001` allowed on the relay device. Peers need outbound TCP access
  to that address and port; replies use the established connection.
- A separate identity file for each peer and an interactive terminal for its CLI.

`peer.py` launches `peer_cli.py`; both accept the same options. `--port 8501`
selects `peer_identity_8501.json`; it **does not open TCP port 8501**. Ports 8501,
8502, and 8503 do not need inbound firewall rules. The network service is the
relay on TCP 4001.

## 1. Install Debian packages on every device

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip ca-certificates unzip iproute2 iputils-ping netcat-openbsd
python3 --version
```

Confirm the version is 3.11 or newer. If your account cannot use `sudo`, ask the
administrator to install these packages, then continue as your normal user.

## 2. Copy the current source to every device

The current working copy may contain fixes that have not been committed and
pushed. Copy the current source when testing those fixes; a clone of the remote
repository only contains its published commits.

### Copy from the current Windows working folder

On the Windows source computer, open PowerShell in the repository root
(`C:\Users\dalme\Documents\minor\Minor`) and run:

```powershell
@'
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

files = [Path("README.md"), Path("p2p-simple/requirements.txt")]
files.extend(sorted(Path("p2p-simple").glob("*.py")))
with ZipFile("minor-lan-source.zip", "w", compression=ZIP_DEFLATED) as archive:
    for path in files:
        archive.write(path, path.as_posix())
print("Created minor-lan-source.zip")
'@ | python -
```

This includes the Python source, tests, requirements, and README, with the
`p2p-simple/` directory structure intact. Identity JSON files, private keys,
virtual environments, and `node_modules` are excluded by the explicit file list.

Copy `minor-lan-source.zip` to your home directory on each Debian device using
a USB drive, shared folder, or your usual file transfer method. On each device:

```bash
mkdir -p ~/minor-lan
unzip ~/minor-lan-source.zip -d ~/minor-lan
cd ~/minor-lan/p2p-simple
ls peer.py peer_cli.py peer_node.py relay.py blockchain.py crypto.py crypto_modular.py requirements.txt
```

For later source updates, stop your peer process before extracting the new
archive. Preserve its identity JSON file to keep the same peer ID.

### Copy from an existing Linux working folder

From that repository's root, create an equivalent source archive:

```bash
tar -czf minor-lan-source.tar.gz README.md p2p-simple/*.py p2p-simple/requirements.txt
```

Copy it to each device's home directory, then extract it:

```bash
mkdir -p ~/minor-lan
tar -xzf ~/minor-lan-source.tar.gz -C ~/minor-lan
cd ~/minor-lan/p2p-simple
```

### Use Git when the required changes have been published

```bash
sudo apt install -y git
git clone https://github.com/errol-dalmeida/Minor_project.git ~/minor-lan
cd ~/minor-lan/p2p-simple
```

Choose one source-copy method. Use the same version on all devices. Each peer
generates its own identity on first launch; copying another peer's identity file
would cause both processes to claim the same peer ID.

## 3. Create the Python environment on every device

From `~/minor-lan/p2p-simple`:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip check
python -c "import sys, cryptography; from peer_node import PeerNode; print(sys.version); print('cryptography', cryptography.__version__); print('PeerNode imports OK')"
python peer.py --help
```

Install application packages inside this environment. Debian's system Python is
externally managed; a virtual environment provides an isolated Python and pip.
See [Debian's Python virtual environment instructions](https://sources.debian.org/src/python3.13/3.13.15-1/debian/README.venv/).

**Every new terminal** needs these two commands before launching the application:

```bash
cd ~/minor-lan/p2p-simple
source .venv/bin/activate
```

If the source has been copied to another location, adjust the `cd` path. Keep
running a peer from the same directory so it finds the same relative identity file.

Most compatible Linux installations can install `cryptography` from a wheel
without compilers after updating pip. If pip must compile it, install the build
packages and check the Rust version:

```bash
sudo apt install -y build-essential libssl-dev libffi-dev python3-dev cargo pkg-config
rustc --version
cargo --version
python -m pip install -r requirements.txt
```

Debian 12's packaged Rust may be too old for recent `cryptography` releases.
If installation reports an unsupported Rust version, install the toolchain
required by the [cryptography installation guide](https://cryptography.io/en/stable/installation/#rust)
and retry inside `.venv`. These build packages are only needed for a source build.

## 4. Find the relay's LAN address and allow its TCP port

On Device A:

```bash
ip -br -4 address
ip -4 route
```

Choose the IPv4 address on the Ethernet/Wi-Fi interface used by Devices B and C,
for example `192.168.1.100`. Peer devices use that address in `--relay`.
`127.0.0.1` refers to the device running the command, so it is appropriate for
Node 1 on Device A, while remote peers use Device A's LAN address.

Keep the relay address stable during the test. A router DHCP reservation is
useful for repeat runs; otherwise recheck the address after reconnecting Wi-Fi.
For a relay inside a VM, configure a reachable bridged LAN interface or forward
the relay's TCP port through the VM host.

If **UFW already manages the relay host**, check it and add a LAN-scoped rule:

```bash
sudo ufw status verbose
sudo ufw allow proto tcp from 192.168.1.0/24 to any port 4001 comment 'P2P relay LAN'
sudo ufw status numbered
```

Replace `192.168.1.0/24` with your actual LAN subnet. If you choose UFW for a
host with no existing firewall manager, install it with `sudo apt install -y ufw`
and add the rule above. Enabling a new UFW firewall is optional for this test;
if you enable it over SSH, allow your SSH port first, for example:

```bash
sudo ufw allow 22/tcp
sudo ufw enable
```

Use your actual SSH port if it differs from 22. UFW activation changes the host's
firewall policy; [Debian's UFW manual](https://manpages.debian.org/trixie/ufw/ufw.8.en.html#REMOTE_MANAGEMENT)
explains remote-management rules. An inactive UFW instance does not enforce its
rules. If nftables or firewalld already manages this device, use that manager to
allow LAN clients to reach TCP 4001.

On hosts with restricted outbound rules, also allow peer connections to the
relay's IPv4 address on TCP 4001. No router Internet port forwarding is needed
for devices that can already reach each other on the LAN.

## 5. Start exactly one relay on Device A

In Device A's **first terminal**:

```bash
cd ~/minor-lan/p2p-simple
source .venv/bin/activate
RELAY_HOST=0.0.0.0 RELAY_PORT=4001 python relay.py
```

Expected output includes `Relay running` and addresses ending in `/tcp/4001/...`.
Keep this terminal running. Peers take `IPv4:port`, such as
`192.168.1.100:4001`, rather than the full printed `/ip4/.../p2p/...` string.

In another terminal on Device A, confirm the listener:

```bash
ss -ltnp 'sport = :4001'
```

It should show port 4001 listening on `0.0.0.0`.

## 6. Check connectivity from Devices B and C

On each remote device, while the relay is running:

```bash
ping -c 3 192.168.1.100
nc -4 -vz -w 3 192.168.1.100 4001
```

Replace the example IP with Device A's address. The TCP check should report
`succeeded`. Ping can be filtered independently, so the TCP check is the relevant
test for this application. See the [Debian netcat manual](https://manpages.debian.org/bookworm/netcat-openbsd/nc.1.en.html).
Resolve a refused or timed-out TCP connection using the troubleshooting table
below before starting peers.

## 7. Start one peer on each device

On Device A, in its **second terminal**:

```bash
cd ~/minor-lan/p2p-simple
source .venv/bin/activate
umask 077
python peer.py --port 8501 --relay 127.0.0.1:4001
```

On Device B:

```bash
cd ~/minor-lan/p2p-simple
source .venv/bin/activate
umask 077
python peer.py --port 8502 --relay 192.168.1.100:4001
```

On Device C:

```bash
cd ~/minor-lan/p2p-simple
source .venv/bin/activate
umask 077
python peer.py --port 8503 --relay 192.168.1.100:4001
```

Replace the remote relay IP in both commands. `umask 077` makes newly created
identity files accessible to their owner. Each terminal should print its peer ID,
`Connected to relay`, and a CLI prompt. The relay should report three connected
peers. Allow the initial key and chain exchanges to finish, then enter these
commands **inside every peer CLI**:

```text
status
peers
trust
crypto sha256 aes-gcm
```

Each peer should list two other connected peers. Copy the full peer IDs into
your test notes as `Node1PeerId`, `Node2PeerId`, and `Node3PeerId`. Replace every
`<Node...PeerId>` placeholder below with that actual ID; omit the angle brackets.

Keep each CLI in the foreground. A peer launched before the relay may enter
offline mode; start the relay, then exit and relaunch that peer.

## 8. Run the tests across the actual LAN devices

Run the scoped/lazy test first, before any successful DM between Nodes 2 and 3.
DM history makes peers active contacts, which changes which peers receive later
scoped notifications. The supplied automated tests run on localhost; the
following manual steps verify the actual devices and LAN connection.

### Test A: scoped revocation, lazy verification, and reinstatement

Inside Node 1 and Node 2:

```text
join #dev
leave #general
channels
```

Inside Node 3:

```text
join #marketing
leave #general
channels
metrics
```

Node 1 and Node 2 should now belong to `#dev`; Node 3 should belong to
`#marketing`. Sharing the default `#general` channel would make all three peers
contacts, so leaving it is part of this test setup.

On Node 2:

```text
revoke 1
metrics
```

On Node 1 and Node 3, inspect:

```text
trust
metrics
```

Expected: Node 1 receives the revocation, marks Node 2 revoked, and sets its trust
to zero. Node 3 receives zero pushed revocation packets; it can still show its
previous local status until it requests an update. With this fresh setup, Node 2
sends one scoped revocation packet, to Node 1.

On Node 3:

```text
dm <Node2PeerId> lazy-check-test
trust
metrics
```

Expected: the DM is blocked; a lazy cache miss triggers an on-demand chain
request; Node 2 becomes revoked with trust zero on Node 3. Node 2 should not print
the message as a received DM. To check local transmission blocking, on Node 2:

```text
#dev this-message-must-be-blocked
broadcast this-broadcast-must-be-blocked
```

Both sends should report a revoked identity. Then reinstate Node 2:

```text
unrevoke
```

Retry on Node 3:

```text
dm <Node2PeerId> hello-after-reinstatement
trust
metrics
```

Expected: Node 3 refreshes the previously revoked recipient, discovers the
reinstatement, sends the DM, and Node 2 displays `hello-after-reinstatement`.
For an explicit fresh check, run `refresh <Node2PeerId>` on Node 3. After this
successful DM, Nodes 2 and 3 are contacts for subsequent scoped updates.

### Test B: confidential direct messages

On Node 1:

```text
dm <Node2PeerId> private-message-from-device-A
```

Expected: Node 2 prints the verified incoming DM; Node 3 does not print it as an
incoming message. Reply from Node 2:

```text
dm <Node1PeerId> reply-from-device-B
```

Node 1 should display the reply. A successful send means the sender wrote the
packet to the relay; the recipient's displayed message confirms application
delivery and verification.

### Test C: channel delivery

On Node 1:

```text
#dev hello-dev-team
```

Expected: Node 2 receives the message; Node 3 does not display it because it has
not joined `#dev`. To test joining the group, on Node 3:

```text
join #dev
```

Send another `#dev` message from Node 1. Both Node 2 and Node 3 should now display
it. Run this step after Test A, since joining `#dev` changes the contact graph.

### Test D: signed public broadcast

On Node 1:

```text
broadcast hello-all-LAN-devices
```

Both other nodes should display the verified broadcast regardless of their
channel membership.

### Test E: key rotation

On Node 2:

```text
status
rotate
status
```

The peer ID should remain the same and its public key should change. On Node 1:

```text
refresh <Node2PeerId>
lookup <Node2PeerId>
dm <Node2PeerId> message-after-key-rotation
```

Node 1 should resolve the new key, and Node 2 should receive the DM. `chain` or
`blocks` displays the signed lifecycle transactions in each peer's local ledger.

### Test F: disconnect and reconnect

On Node 3, enter `exit`. Nodes 1 and 2 should report that it left. Relaunch Node 3
from its Linux shell using the same command, directory, and identity file as in
step 7. Its peer ID should remain the same, and `peers` should again show two
other nodes. Use `join #dev` again if you want to restore that channel membership.

For a relay restart test, press `Ctrl+C` in Device A's relay terminal, leaving
the peer terminals running. Start the relay again with the command in step 5.
Already-connected peers should report disconnection and retry the relay roughly
every two seconds. Once reconnected, verify `peers` and send another DM.

Record the result of Tests A-F, the devices' IPs, peer IDs, Python/cryptography
versions, and any failed command or receiver output. This distinguishes a LAN
connectivity failure from a key, cache, or messaging failure.

## Terminal commands

| Command | Action |
| --- | --- |
| `menu` / `help` | Guided numbered menu / command reference |
| `peers` / `status` | Peer IDs, connections, local identity and ledger status |
| `dm <peerId-or-prefix> <message>` | Encrypted, signed direct message |
| `@<peerId-or-prefix> <message>` | Alternative direct message syntax |
| `join #dev` / `leave #dev` | Join or leave a channel, including `#general` |
| `channel #dev` / `channels` | Choose an active channel / list memberships |
| `#dev <message>` / `<message>` | Message a named channel / the active channel |
| `broadcast <message>` | Signed public broadcast |
| `revoke [1-4]` | Revoke the current identity; notify active contacts |
| `unrevoke` / `reinstate` | Reinstate the current key |
| `rotate` | Generate and publish a replacement keypair |
| `lookup <peerId-or-prefix>` | Read a local ledger identity record |
| `refresh <peerId-or-prefix>` | Request current status, bypassing the cache |
| `trust` / `metrics` | Trust matrix / push packets, cache hits, misses and TTLs |
| `chain` / `blocks` | Inspect ledger blocks and transactions |
| `crypto sha256 aes-gcm` | Select SHA-256 and AES-GCM |
| `crypto blake2b chacha20` | Select BLAKE2b and ChaCha20-Poly1305 |
| `exit` / `quit` | Disconnect and stop the peer |

Use crypto settings that match on communicating peers. Cipher/hash changes are
not negotiated automatically. A successful send means the relay accepted the
write; the receiving terminal separately prints the verified incoming message.

## Identity persistence and cache behavior

Peer IDs and keys survive restarts in their identity JSON files. Channel
memberships, DM history, trust state, cached statuses, and ledgers are in memory.
Restarted peers learn ledger state from connected peers. If every peer stops,
there is currently no persisted ledger from which to restore the complete
revocation and rotation history. Rejoin your test channels after restarting.

For a clean repeat of Test A, exit and relaunch all peers, preserve their identity
files, and apply the separate channel setup before sending any DMs. A new
identity can instead be created with an unused `--id-file` path. Treat these
files as private key material belonging to the individual peer.

Positive verification entries have a default 300-second TTL. Scoped lifecycle
updates immediately refresh known state; unrelated peers can retain an earlier
active result until expiry or a forced refresh. An unavailable chain reply cannot
create a fresh active entry. This cache policy does not guarantee instantaneous
revocation knowledge for every disconnected or unrelated peer.

Channel keys currently derive from public channel names. These are demonstration
groups, not access-controlled private rooms. The native ledger and single relay
are a LAN prototype; this is not a production consensus or routing system.

## Automated verification

On each Debian device, use another terminal and the environment from step 3:

```bash
cd ~/minor-lan/p2p-simple
source .venv/bin/activate
python test_peer_revocation_regressions.py
python test_efficient_revocation.py
python test_modular_crypto.py
python test_dpki.py
python test_network_e2e.py
```

The regression suite covers stale caches, reinstatement, TTL expiry, forged
transactions, signature checks, delayed and missing chain replies, shorter forks,
relay reconnection, and a real three-node revoke/block/reinstate/resume sequence.
The scoped benchmark uses four peers in separate groups and checks packet counts
without manually injecting peer keys or channel memberships.

These scripts start isolated localhost test relays. They check application
behavior but do not prove that separate LAN devices can communicate. Complete
the manual LAN tests in step 8 as well. The network scripts use test ports 4009,
4015, 4099, and an automatically assigned port; they do not replace the live
relay on 4001.

## Troubleshooting on Debian

| Symptom | Check and next step |
| --- | --- |
| `python: command not found` | Activate `.venv`; create it with `python3 -m venv .venv` if needed. |
| `externally-managed-environment` | Run pip after `source .venv/bin/activate`. `which python` should point into this project's `.venv/bin/`. |
| `ensurepip` unavailable or virtual environment creation fails | Install `python3-venv`, then run `python3 -m venv .venv` again. |
| `ModuleNotFoundError: cryptography` | In the active environment, run `python -m pip install -r requirements.txt`. |
| Missing `peer_cli`, `peer_node`, or another project module | Copy the complete current Python source and run from `p2p-simple`. A stale Git clone may lack the CLI changes. |
| Failed wheel build or unsupported Rust | Upgrade pip inside `.venv`; see the source-build instructions in step 3. |
| `nc` reports connection refused | Start the relay, verify its IP/port, and check `ss -ltnp 'sport = :4001'` on the relay device. Check for firewall rejection as well. |
| `nc` times out | Check the subnet, route, relay firewall, AP/client isolation, and any VM networking. The remote endpoint must be the relay's LAN IP. |
| Relay cannot bind because port 4001 is in use | Check the listener with `ss`; use the intended existing relay or select another `RELAY_PORT` and update every peer endpoint and firewall rule. |
| Peer says it is running offline | Verify TCP connectivity and restart the peer after the relay is available. |
| A peer repeatedly disconnects when another launches | Check that the two processes are not sharing a copied identity JSON file. Relaunch the affected test peer with an unused `--id-file` name. |
| DM target is not found | Use the peer ID from `peers`, rather than its IP address. Copy the full ID to avoid an ambiguous short prefix. |
| Channel decryption fails | Match crypto settings on all participants using `crypto sha256 aes-gcm`; verify that each receiver joined the channel. |
| Node 3 receives a revocation push during Test A | It may still share `#general` or another channel, or have DM history with Node 2. Restart peers and perform Test A before the other messaging tests. |
| Node 3 reports a cache hit instead of the expected first miss | Start with fresh peer processes for Test A. A previous `refresh` or message may already have populated the cache. |
| `SYNC_UNAVAILABLE` or a chain request timeout | Confirm both peers are connected and use the same current source. Run `refresh <peerId>` once the network is responsive. |
| Icons appear as squares | Use a UTF-8 terminal with suitable fonts; judge tests by message text, connection state, and metrics. |

## Shut down and restart

Enter `exit` in each peer CLI, then press `Ctrl+C` in the relay terminal.
To restart, activate the environment in every terminal, start the relay first,
and rerun the device-specific peer commands from step 7. Run `deactivate` in a
Linux shell when you have finished using its virtual environment.
