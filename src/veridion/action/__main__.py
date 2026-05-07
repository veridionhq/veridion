"""CLI entrypoint for the Veridion GitHub Action runner."""

from veridion.action.runner import main


if __name__ == "__main__":
    raise SystemExit(main())
