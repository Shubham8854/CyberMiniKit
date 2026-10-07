import re

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "iloveyou",
    "abc123",
}


def check_password(password):
    """Analyze a password and return security findings."""

    score = 0
    findings = []
    recommendations = []

    length = len(password)

    # Length
    if length >= 16:
        score += 2
        length_status = "Excellent"
    elif length >= 12:
        score += 1
        length_status = "Good"
    elif length >= 8:
        length_status = "Weak"
        recommendations.append("Use at least 12 characters.")
    else:
        length_status = "Very Weak"
        recommendations.append("Use at least 12 characters.")

    # Character checks
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))

    checks = [
        ("Uppercase", has_upper),
        ("Lowercase", has_lower),
        ("Number", has_digit),
        ("Special Character", has_special),
    ]

    for name, passed in checks:
        if passed:
            score += 1
        else:
            recommendations.append(f"Add at least one {name.lower()}.")

    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        score = 0
        findings.append("This password appears in a common-password list.")
        recommendations.append("Avoid commonly used passwords.")

    # Repeated character check
    if re.search(r"(.)\1{2,}", password):
        score = max(0, score - 1)
        findings.append("The password contains repeated characters.")
        recommendations.append("Avoid predictable repeated characters.")

    # Sequential characters
    sequences = [
        "123",
        "234",
        "345",
        "456",
        "567",
        "678",
        "789",
        "abc",
        "bcd",
        "cde",
        "qwe",
        "wer",
        "ert",
    ]

    if any(sequence in password.lower() for sequence in sequences):
        score = max(0, score - 1)
        findings.append("The password contains predictable sequences.")
        recommendations.append("Avoid keyboard or numeric sequences.")

    # Determine rating
    if score >= 7:
        rating = "VERY STRONG"
    elif score >= 5:
        rating = "STRONG"
    elif score >= 3:
        rating = "MODERATE"
    elif score >= 1:
        rating = "WEAK"
    else:
        rating = "VERY WEAK"

    return {
        "length": length,
        "length_status": length_status,
        "checks": checks,
        "score": score,
        "rating": rating,
        "findings": findings,
        "recommendations": recommendations,
    }


def run_password_checker():
    console.clear()

    console.print(
        Panel(
            "[bold cyan]PASSWORD STRENGTH CHECKER[/bold cyan]\n"
            "[dim]Analyze password complexity and identify weaknesses[/dim]",
            border_style="cyan",
        )
    )

    password = console.input(
        "\n[bold cyan]Enter password to analyze: [/bold cyan]"
    )

    if not password:
        console.print("[bold red]Password cannot be empty.[/bold red]")
        console.input("\nPress Enter to return...")
        return

    result = check_password(password)

    table = Table(
        title="Password Analysis",
        border_style="cyan",
    )

    table.add_column("Check", style="bold white")
    table.add_column("Result", style="bold")

    table.add_row(
        "Length",
        f"{result['length']} characters ({result['length_status']})",
    )

    for name, passed in result["checks"]:
        status = "[green]PASS[/green]" if passed else "[red]FAIL[/red]"
        table.add_row(name, status)

    table.add_row(
        "Security Score",
        f"[bold]{result['score']}/7[/bold]",
    )

    table.add_row(
        "Overall Rating",
        f"[bold yellow]{result['rating']}[/bold yellow]",
    )

    console.print(table)

    if result["findings"]:
        console.print("\n[bold red]Findings[/bold red]")

        for finding in result["findings"]:
            console.print(f"  • {finding}")

    if result["recommendations"]:
        console.print("\n[bold yellow]Recommendations[/bold yellow]")

        for recommendation in result["recommendations"]:
            console.print(f"  • {recommendation}")
    else:
        console.print(
            "\n[bold green]✓ No major password weaknesses detected.[/bold green]"
        )

    console.input("\n[dim]Press Enter to return to the main menu...[/dim]")
