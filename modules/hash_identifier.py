import re

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


HASH_PATTERNS = [
    ("MD5", r"^[a-fA-F0-9]{32}$"),
    ("SHA-1", r"^[a-fA-F0-9]{40}$"),
    ("SHA-224", r"^[a-fA-F0-9]{56}$"),
    ("SHA-256", r"^[a-fA-F0-9]{64}$"),
    ("SHA-384", r"^[a-fA-F0-9]{96}$"),
    ("SHA-512", r"^[a-fA-F0-9]{128}$"),
    ("bcrypt", r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"),
    ("Argon2", r"^\$argon2(id|i|d)\$.*"),
]


def identify_hash(hash_value):
    """Identify likely hash algorithms based on format."""

    value = hash_value.strip()

    if not value:
        return {
            "valid": False,
            "hash": "",
            "matches": [],
        }

    matches = []

    for algorithm, pattern in HASH_PATTERNS:
        if re.fullmatch(pattern, value):
            matches.append(algorithm)

    if matches:
        return {
            "valid": True,
            "hash": value,
            "matches": matches,
        }

    return {
        "valid": True,
        "hash": value,
        "matches": [],
    }


def run_hash_identifier():
    console.clear()

    console.print(
        Panel(
            "[bold cyan]HASH IDENTIFIER[/bold cyan]\n"
            "[dim]Identify likely hash algorithms from their format[/dim]",
            border_style="cyan",
        )
    )

    hash_value = console.input(
        "\n[bold cyan]Enter hash: [/bold cyan]"
    ).strip()

    result = identify_hash(hash_value)

    if not result["hash"]:
        console.print(
            "\n[bold red]Error:[/bold red] Hash cannot be empty."
        )
        console.input("\n[dim]Press Enter to return to menu...[/dim]")
        return

    table = Table(
        title="Hash Analysis",
        border_style="cyan",
    )

    table.add_column("Property", style="bold white")
    table.add_column("Result", style="bold")

    table.add_row(
        "Length",
        f"{len(result['hash'])} characters",
    )

    table.add_row(
        "Hexadecimal",
        "[green]YES[/green]"
        if re.fullmatch(r"[a-fA-F0-9]+", result["hash"])
        else "[yellow]NO[/yellow]",
    )

    if result["matches"]:
        table.add_row(
            "Likely Algorithm",
            ", ".join(result["matches"]),
        )
    else:
        table.add_row(
            "Likely Algorithm",
            "Unknown",
        )

    console.print(table)

    if result["matches"]:
        console.print(
            "\n[bold green]✓ Possible hash type identified.[/bold green]"
        )

        console.print(
            "\n[bold yellow]Note:[/bold yellow] "
            "Format-based identification is not proof of the algorithm."
        )
    else:
        console.print(
            "\n[bold yellow]⚠ Hash type could not be identified "
            "from its format.[/bold yellow]"
        )

    console.input(
        "\n[dim]Press Enter to return to the main menu...[/dim]"
    )
