"""Release artifact signing."""


def main() -> None:
    from .sign_cli import main as cli_main

    cli_main()
