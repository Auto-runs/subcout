"""Allow running as `python -m subscout`."""
from subscout.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
