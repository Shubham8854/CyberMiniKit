from urllib.parse import urlparse
import ipaddress
import re

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def check_url(url):
    """Analyze a URL for common security indicators."""

    original_url = url.strip()

    if not original_url:
        return {
            "valid": False,
            "error": "URL cannot be empty.",
        }

    # Add scheme if the user only enters a domain
    normalized_url = original_url

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", normalized_url):
        normalized_url = "https://" + normalized_url

    try:
        parsed = urlparse(normalized_url)
    except ValueError:
        return {
            "valid": False,
            "error": "Invalid URL format.",
        }

    if not parsed.netloc:
        return {
            "valid": False,
            "error": "Could not identify a domain or host.",
        }

    hostname = parsed.hostname

    if not hostname:
        return {
            "valid": False,
            "error": "Could not identify hostname.",
        }

    findings = []
    recommendations = []
    score = 100

    # HTTPS check
    if parsed.scheme.lower() == "https":
        https_status = "SECURE"
    else:
        https_status = "INSECURE"
        score -= 30
        findings.append("The URL does not use HTTPS.")
        recommendations.append("Use HTTPS whenever possible.")

    # IP address check
    is_ip = False

    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        pass

    if is_ip:
        score -= 15
        findings.append("The URL uses a direct IP address.")
        recommendations.append(
            "Prefer a trusted domain name instead of a direct IP address."
        )

    # Non-standard port check
    port = parsed.port

    if port is not None:
        if port not in {80, 443}:
            score -= 15
            findings.append(
                f"The URL uses a non-standard port ({port})."
            )
            recommendations.append(
                "Verify that the non-standard port is expected."
            )

    # URL length
    if len(original_url) > 200:
        score -= 10
        findings.append("The URL is unusually long.")
        recommendations.append(
            "Verify long URLs carefully before accessing them."
        )

    # Suspicious characters
    suspicious_patterns = [
        (r"@", "The URL contains '@', which can obscure the actual host."),
        (r"\.\.", "The URL contains consecutive dots."),
        (r"%", "The URL contains encoded characters."),
    ]

    for pattern, message in suspicious_patterns:
        if re.search(pattern, original_url):
            score -= 5
            findings.append(message)

    # Hyphen-heavy hostname
    if hostname.count("-") >= 3:
        score -= 5
        findings.append(
            "The hostname contains several hyphens."
        )
        recommendations.append(
            "Verify the domain carefully for impersonation."
        )

    # Subdomain check
    subdomain_count = max(0, len(hostname.split(".")) - 2)

    if subdomain_count >= 3:
        score -= 5
        findings.append(
            "The URL contains multiple subdomain levels."
        )
        recommendations.append(
            "Verify that the complete domain belongs to the expected organization."
        )

    score = max(0, score)

    if score >= 85:
        rating = "LOW RISK"
    elif score >= 65:
        rating = "MEDIUM RISK"
    else:
        rating = "HIGH RISK"

    return {
        "valid": True,
        "original_url": original_url,
        "normalized_url": normalized_url,
        "scheme": parsed.scheme,
        "hostname": hostname,
        "port": port if port else "Default",
        "https": https_status,
        "is_ip": is_ip,
        "length": len(original_url),
        "score": score,
        "rating": rating,
        "findings": findings,
        "recommendations": recommendations,
    }


def run_url_checker():
    console.clear()

    console.print(
        Panel(
            "[bold cyan]URL / DOMAIN SECURITY CHECKER[/bold cyan]\n"
            "[dim]Analyze common URL security indicators[/dim]",
            border_style="cyan",
        )
    )

    url = console.input(
        "\n[bold cyan]Enter URL or domain: [/bold cyan]"
    ).strip()

    result = check_url(url)

    if not result["valid"]:
        console.print(
            f"\n[bold red]Error:[/bold red] {result['error']}"
        )
        console.input("\n[dim]Press Enter to return to menu...[/dim]")
        return

    table = Table(
        title="URL Security Analysis",
        border_style="cyan",
    )

    table.add_column("Check", style="bold white")
    table.add_column("Result", style="bold")

    table.add_row("URL", result["original_url"])
    table.add_row("Hostname", result["hostname"])
    table.add_row("Protocol", result["scheme"].upper())
    table.add_row(
        "HTTPS",
        "[green]SECURE[/green]"
        if result["https"] == "SECURE"
        else "[red]INSECURE[/red]",
    )
    table.add_row(
        "Direct IP",
        "[yellow]YES[/yellow]"
        if result["is_ip"]
        else "[green]NO[/green]",
    )
    table.add_row("Port", str(result["port"]))
    table.add_row("URL Length", f"{result['length']} characters")
    table.add_row("Security Score", f"{result['score']}/100")
    table.add_row("Risk Rating", result["rating"])

    console.print(table)

    if result["findings"]:
        console.print("\n[bold red]Findings[/bold red]")

        for finding in result["findings"]:
            console.print(f"  • {finding}")
    else:
        console.print(
            "\n[bold green]✓ No major URL security indicators detected.[/bold green]"
        )

    if result["recommendations"]:
        console.print("\n[bold yellow]Recommendations[/bold yellow]")

        for recommendation in result["recommendations"]:
            console.print(f"  • {recommendation}")

    console.input(
        "\n[dim]Press Enter to return to the main menu...[/dim]"
    )
