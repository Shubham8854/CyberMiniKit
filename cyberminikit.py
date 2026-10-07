from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from modules.password_checker import run_password_checker
from modules.url_checker import run_url_checker
from modules.hash_identifier import run_hash_identifier
from modules.file_integrity import run_file_integrity
from modules.log_analyzer import run_log_analyzer


console = Console()


def show_banner():
    console.clear()

    banner = r"""
   ██████╗██╗   ██╗██████╗ ███████╗██████╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗
  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
    """

    console.print(
        Panel(
            f"[bold cyan]{banner}[/bold cyan]\n"
            "[bold white]Cybersecurity Mini Toolkit[/bold white]\n"
            "[dim]Five practical security utilities in one toolkit[/dim]",
            border_style="cyan",
            padding=(1, 2),
        )
    )


def show_menu():
    table = Table(
        title="CYBERMINIKIT",
        box=box.ROUNDED,
        border_style="cyan",
        title_style="bold cyan",
    )

    table.add_column(
        "ID",
        style="bold yellow",
        justify="center",
    )

    table.add_column(
        "Security Tool",
        style="bold white",
    )

    table.add_column(
        "Purpose",
        style="dim",
    )

    table.add_row(
        "1",
        "Password Strength Checker",
        "Analyze password security",
    )

    table.add_row(
        "2",
        "URL / Domain Security Checker",
        "Inspect URL security",
    )

    table.add_row(
        "3",
        "Hash Identifier",
        "Identify common hash types",
    )

    table.add_row(
        "4",
        "File Integrity Checker",
        "Detect file modifications",
    )

    table.add_row(
        "5",
        "Log Analyzer",
        "Analyze security-related logs",
    )

    table.add_row(
        "0",
        "Exit",
        "Close CyberMiniKit",
    )

    console.print(table)


def main():
    while True:
        show_banner()
        show_menu()

        choice = console.input(
            "\n[bold cyan]CyberMiniKit[/bold cyan] "
            "[white]> Select an option: [/white]"
        ).strip()

        if choice == "0":
            console.print(
                "\n[bold green]Goodbye! Stay secure. 🛡️[/bold green]\n"
            )
            break

        elif choice == "1":
            run_password_checker()

        elif choice == "2":
            run_url_checker()

        elif choice == "3":
            run_hash_identifier()

        elif choice == "4":
            run_file_integrity()

        elif choice == "5":
            run_log_analyzer()

        else:
            console.print(
                "\n[bold red]Invalid option.[/bold red] "
                "Please select 0-5."
            )

            console.input(
                "\n[dim]Press Enter to continue...[/dim]"
            )


if __name__ == "__main__":
    main()
