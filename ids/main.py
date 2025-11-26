import argparse
from importlib import import_module

# Try a relative import first (works when run as a package), then try the local package name,
# and finally fall back to a plain import when running the module as a script.
try:
    from .capture import PacketCapture
except Exception:
    try:
        PacketCapture = import_module("ids.capture").PacketCapture
    except Exception:
        from capture import PacketCapture

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", type=str, default=None)
    args = parser.parse_args()

    pc = PacketCapture(iface=args.iface)
    pc.start()

if __name__ == "__main__":
    main()