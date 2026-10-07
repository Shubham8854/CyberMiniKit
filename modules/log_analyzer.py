import re
from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


FAILED_PATTERNS = [
    r"failed password",
    r"authentication failure",
    r"invalid user",
    r"login failed",
    r"failed login",
    r"unauthorized",
    r"access denied",
]

SUCCESS_PATTERNS = [
    r"accepted password",
    r"accepted publickey",
    r"login successful",
    r"authentication successful",
]


def analyze_log(file_path):
    """Analyze a log file for common security events."""

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Log file not found: {file_path}"
        )

    failed_events = []
    successful_events = []
    ip_addresses = []

    ip_pattern = re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    )

    with path.open(
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as file:

        for line_number, line in enumerate(
            file,
            start=1,
        ):
            lower_line = line.lower()

            if any(
                re.search(pattern, lower_line)
                for pattern in FAILED_PATTERNS
            ):
                failed_events.append(
                    (line_number, line.strip())
                )

            if any(
                re.search(pattern, lower_line)
                for pattern in SUCCESS_PATTERNS
            ):
                successful_events.append(
                    (line_number, line.strip())
                )

            ip_addresses.extend(
                ip_pattern.findall(line)
            )

    return (
        failed_events,
        successful_events,
        ip_addresses,
    )


def show_ip_analysis(ip_addresses):
    """Display IP address statistics."""

    table = Table(
        title="Top IP Addresses",
        border_style="cyan",
    )

    table.add_column(
        "IP Address",
        style="bold white",
    )

    table.add_column(
        "Occurrences",
        style="bold yellow",
        justify="center",
    )

    counter = Counter(ip_addresses)

    for ip, count in counter.most_common(10):
        table.add_row(
            ip,
            str(count),
        )

    if not counter:
        table.add_row(
            "None detected",
            "-",
        )

    console.print(table)


def run_log_analyzer():
    console.clear()

    console.print(
        Panel(
            "[bold cyan]LOG ANALYZER[/bold cyan]\n"
            "[dim]Analyze logs for authentication and security events[/dim]",
            border_style="cyan",
        )
    )

    file_path = console.input(
        "\n[bold cyan]Enter log file path: [/bold cyan]"
    ).strip()

    path = Path(file_path)

    if not path.is_file():
        console.print(
            "\n[bold red]Error:[/bold red] "
            "Log file does not exist."
        )

        console.input(
            "\n[dim]Press Enter to return to the main menu...[/dim]"
        )
        return

    try:
        (
            failed_events,
            successful_events,
            ip_addresses,
        ) = analyze_log(path)

    except Exception as error:
        console.print(
            f"\n[bold red]Error:[/bold red] {error}"
        )

        console.input(
            "\n[dim]Press Enter to return to the main menu...[/dim]"
        )
        return

    total_events = (
        len(failed_events)
        + len(successful_events)
    )

    table = Table(
        title="Log Analysis Summary",
        border_style="cyan",
    )

    table.add_column(
        "Security Metric",
        style="bold white",
    )

    table.add_column(
        "Count",
        style="bold yellow",
        justify="center",
    )

    table.add_row(
        "Failed Authentication Events",
        str(len(failed_events)),
    )

    table.add_row(
        "Successful Authentication Events",
        str(len(successful_events)),
    )

    table.add_row(
        "Detected IP Addresses",
        str(len(set(ip_addresses))),
    )

    table.add_row(
        "Total Security Events",
        str(total_events),
    )

    console.print(table)

    if failed_events:
        console.print(
            "\n[bold red]⚠ Failed Authentication Events[/bold red]"
        )

        failed_table = Table(
            border_style="red",
        )

        failed_table.add_column(
            "Line",
            style="bold yellow",
            justify="center",
        )

        failed_table.add_column(
            "Log Entry",
            style="white",
        )

        for line_number, entry in failed_events[:10]:
            failed_table.add_row(
                str(line_number),
                entry[:120],
            )

        console.print(failed_table)

    else:
        console.print(
            "\n[bold green]✓ No failed authentication "
            "events detected.[/bold green]"
        )

    if successful_events:
        console.print(
            "\n[bold green]✓ Successful Authentication Events[/bold green]"
        )

        success_table = Table(
            border_style="green",
        )

        success_table.add_column(
            "Line",
            style="bold yellow",
            justify="center",
        )

        success_table.add_column(
            "Log Entry",
            style="white",
        )

        for line_number, entry in successful_events[:10]:
            success_table.add_row(
                str(line_number),
                entry[:120],
            )

        console.print(success_table)

    show_ip_analysis(ip_addresses)

    if len(failed_events) >= 10:
        console.print(
            "\n[bold red]HIGH ATTENTION:[/bold red] "
            "A large number of failed authentication events "
            "were detected."
        )
        console.print(
            "[yellow]Recommendation:[/yellow] "
            "Investigate the source IPs and review authentication controls."
        )

    elif failed_events:
        console.print(
            "\n[bold yellow]ATTENTION:[/bold yellow] "
            "Failed authentication events were detected."
        )
        console.print(
            "[yellow]Recommendation:[/yellow] "
            "Review the related log entries and source IP addresses."
        )

    else:
        console.print(
            "\n[bold green]Log analysis completed successfully.[/bold green]"
        )

    console.input(
        "\n[dim]Press Enter to return to the main menu...[/dim]"
    )
