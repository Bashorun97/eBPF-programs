# EBPF programs
### To use on Linux:
- Clone repo
- Ensure docker is installed
- Run `./ebpf_setup.sh`

### To use on MacOS:
Install Colima
```
# Homebrew
brew install colima

# MacPorts
sudo port install colima

# Nix
nix-env -iA nixpkgs.colima

# Mise
mise use -g colima@latest
```

Spin up a VM with QEMU set to vm-type
```
colima start ebpf --vm-type=qemu
```

SSH into Colima profile
```
colima ssh -p ebpf
```

You can then `cd` into any directory and execute your eBPF program of choice in sudo mode.

Example:
```
cd packet-tracer

sudo python3 ./tracer.py
```