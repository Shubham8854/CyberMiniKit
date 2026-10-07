import hashlib
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


SUPPORTED_ALGORITHMS = {
    "1": "sha256",
    "2": "sha512",
    "3": "md5",
}


def calculate_hash(file_path, algorithm="sha256"):
    """Calculate a cryptographic hash for a file."""

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    hash_object = hashlib.new(algorithm)

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            hash_object.update(chunk)

    return hash_object.hexdigest()


def compare_hashes(original_hash, current_hash):
    """Compare two hashes."""

    return (
        original_hash.strip().lower()
        == current_hash.strip().lower()
    )


def run_file_integrity():
    console.clear()

    console.print(
        Panel(
            "[bold cyan]FILE INTEGRITY CHECKER[/bold cyan]\n"
            "[dim]Detect file modifications using cryptographic hashes[/dim]",
            border_style="cyan",
        )
    )

    file_path = console.input(
        "\n[bold cyan]Enter file path: [/bold cyan]"
    ).strip()

    path = Path(file_path)

    if not path.is_file():
        console.print(
            "\n[bold red]Error:[/bold red] File does not exist."
        )
        console.input(
            "\n[dim]Press Enter to return to the main menu...[/dim]"
        )
        return

    console.print(
        "\n[bold cyan]Select hashing algorithm:[/bold cyan]"
    )

    console.print("  [yellow]1[/yellow] - SHA-256")
    console.print("  [yellow]2[/yellow] - SHA-512")
    console.print("  [yellow]3[/yellow] - MD5")

    algorithm_choice = console.input(
        "\n[bold cyan]Select algorithm: [/bold cyan]"
    ).strip()

    algorithm = SUPPORTED_ALGORITHMS.get(
        algorithm_choice,
        "sha256",
    )

    try:
        current_hash = calculate_hash(
            path,
            algorithm,
        )
    except Exception as error:
        console.print(
            f"\n[bold red]Error:[/bold red] {error}"
        )
        console.input(
            "\n[dim]Press Enter to return to the main menu...[/dim]"
        )
        return

    table = Table(
        title="File Integrity Analysis",
        border_style="cyan",
    )

    table.add_column("Property", style="bold white")
    table.add_column("Result", style="bold")

    table.add_row(
        "File",
        str(path),
    )

    table.add_row(
        "Size",
        f"{path.stat().st_size:,} bytes",
    )

    table.add_row(
        "Algorithm",
        algorithm.upper(),
    )

    table.add_row(
        "Current Hash",
        current_hash,
    )

    console.print(table)

    console.print(
        "\n[bold cyan]Integrity Verification[/bold cyan]"
    )

    original_hash = console.input(
        "[bold cyan]Enter original/reference hash "
        "(or press Enter to skip): [/bold cyan]"
    ).strip()

    if original_hash:
        if compare_hashes(
            original_hash,
            current_hash,
        ):
            console.print(
                "\n[bold green]✓ INTEGRITY OK[/bold green]"
            )
            console.print(
                "[green]The current file hash matches the reference hash.[/green]"
            )
        else:
            console.print(
                "\n[bold red]✗ FILE MODIFIED[/bold red]"
            )
            console.print(
                "[red]The current file hash does not match the reference hash.[/red]"
            )

            console.print(
                "\n[bold yellow]Recommendation:[/bold yellow]"
            )
            console.print(
                "  • Investigate the file before trusting its contents."
            )
    else:
        console.print(
            "\n[bold yellow]Reference hash not provided.[/bold yellow]"
        )

        console.print(
            "[dim]Save the current hash as a trusted reference "
            "for future integrity checks.[/dim]"
        )

    console.input(
        "\n[dim]Press Enter to return to the main menu...[/dim]"
    )
