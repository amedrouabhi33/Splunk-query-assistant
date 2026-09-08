import os
import re
import time

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

from queries import load_queries


console = Console()

# Load the enriched JSON database
QUERIES = load_queries()


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def get_mitre_info(item):
    """
    Return MITRE values safely.

    Priority:
    1. Use mitre_id / mitre_name / mitre_tactic / mitre_url
    2. If those are missing or N/A, try to parse the older 'mitre' field
       when it contains something like:
       'T1110 - Brute Force'
    3. If the detection is truly environment-dependent, show a useful
       message instead of plain 'N/A'.
    """
    mitre_id = str(item.get("mitre_id", "")).strip()
    mitre_name = str(item.get("mitre_name", "")).strip()
    mitre_tactic = str(item.get("mitre_tactic", "")).strip()
    mitre_url = str(item.get("mitre_url", "")).strip()

    old_mitre = str(item.get("mitre", "")).strip()

    invalid = {"", "N/A", "NA", "NONE", "ENVIRONMENT DEPENDENT"}

    # Fallback to the legacy "mitre" field if possible
    if mitre_id.upper() in invalid:
        match = re.match(r"^(T\d+(?:\.\d+)?)\s*-\s*(.+)$", old_mitre)

        if match:
            mitre_id = match.group(1)
            mitre_name = match.group(2)

            if not mitre_url or mitre_url.upper() in invalid:
                mitre_url = (
                    "https://attack.mitre.org/techniques/"
                    + mitre_id.replace(".", "/")
                    + "/"
                )

    # If still not mapped, display something meaningful
    if not mitre_id or mitre_id.upper() in invalid:
        mitre_id = "Unmapped"

    if not mitre_name or mitre_name.upper() in invalid:
        mitre_name = "Environment Dependent"

    if not mitre_tactic or mitre_tactic.upper() in invalid:
        mitre_tactic = "Environment Dependent"

    if not mitre_url or mitre_url.upper() in invalid:
        mitre_url = "No specific ATT&CK mapping"

    return mitre_id, mitre_name, mitre_tactic, mitre_url


def severity_markup(severity):
    severity = str(severity or "N/A")

    if severity.lower() == "critical":
        return "[bold red]Critical[/bold red]"
    if severity.lower() == "high":
        return "[red]High[/red]"
    if severity.lower() == "medium":
        return "[yellow]Medium[/yellow]"
    if severity.lower() == "low":
        return "[green]Low[/green]"

    return severity


def banner():
    clear_screen()

    console.print(
        Panel.fit(
            "[bold cyan]SPLUNK QUERY ASSISTANT[/bold cyan]\n"
            "[green]SOC Detection & Investigation Toolkit[/green]\n"
            f"[dim]{len(QUERIES)} Splunk Queries • Created by SnipTe$t[/dim]",
            border_style="cyan",
            box=box.DOUBLE,
        )
    )


def loading_animation():
    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task(
            "Loading Splunk detection library...",
            total=None,
        )

        time.sleep(0.3)

        progress.update(
            task,
            description="Loading MITRE ATT&CK mappings...",
        )

        time.sleep(0.3)

    console.print(
        f"[bold green]✓ {len(QUERIES)} queries loaded successfully[/bold green]\n"
    )


def show_menu():
    table = Table(
        title=f"Splunk SOC Query Library — {len(QUERIES)} Queries",
        box=box.ROUNDED,
        show_lines=False,
    )

    table.add_column("ID", justify="right", style="bold cyan", width=5)
    table.add_column("Detection / Use Case", style="white")
    table.add_column("MITRE", style="magenta")
    table.add_column("Severity")

    for item in QUERIES:
        mitre_id, _, _, _ = get_mitre_info(item)

        table.add_row(
            f"{item['number']:03}",
            item["name"],
            mitre_id,
            severity_markup(item.get("severity", "N/A")),
        )

    console.print(table)

    console.print(
        "\n[cyan]Commands:[/cyan] "
        f"[green]1-{len(QUERIES)}[/green] | "
        "[yellow]search[/yellow] | "
        "[magenta]mitre[/magenta] | "
        "[blue]list[/blue] | "
        "[red]exit[/red]"
    )


def show_query(index):
    item = QUERIES[index]

    mitre_id, mitre_name, mitre_tactic, mitre_url = get_mitre_info(item)

    console.print(
        Panel(
            f"[bold cyan]#{item['number']:03} {item['name']}[/bold cyan]",
            title="Detection Details",
            border_style="cyan",
        )
    )

    # MITRE ATT&CK INFORMATION
    mitre_table = Table(
        title="MITRE ATT&CK",
        box=box.ROUNDED,
        show_header=False,
    )

    mitre_table.add_column("Field", style="bold cyan")
    mitre_table.add_column("Value", style="white")

    mitre_table.add_row("Technique ID", mitre_id)
    mitre_table.add_row("Technique", mitre_name)
    mitre_table.add_row("Tactic", mitre_tactic)
    mitre_table.add_row("MITRE URL", mitre_url)

    console.print(mitre_table)

    if mitre_id == "Unmapped":
        console.print(
            "[dim yellow]This detection is not assigned to one specific "
            "MITRE ATT&CK technique in the current JSON database.[/dim yellow]"
        )

    # DETECTION INFORMATION
    detection_table = Table(
        title="Detection Information",
        box=box.ROUNDED,
        show_header=False,
    )

    detection_table.add_column("Field", style="bold green")
    detection_table.add_column("Value")

    detection_table.add_row(
        "Severity",
        severity_markup(item.get("severity", "N/A")),
    )
    detection_table.add_row(
        "Category",
        item.get("category", "N/A"),
    )
    detection_table.add_row(
        "Log Source",
        item.get("log_source", "N/A"),
    )

    console.print(detection_table)

    # DESCRIPTION
    console.print(
        Panel(
            item.get("description", "N/A"),
            title="Description",
            border_style="blue",
        )
    )

    # REQUIRED FIELDS
    fields = item.get("required_fields", [])

    if fields:
        console.print("\n[bold cyan]Required Fields[/bold cyan]")

        for field in fields:
            console.print(f"  [green]•[/green] {field}")

    # SPLUNK QUERY
    syntax = Syntax(
        item.get("query", ""),
        "text",
        theme="monokai",
        word_wrap=True,
    )

    console.print(
        Panel(
            syntax,
            title="Splunk SPL Query",
            border_style="green",
        )
    )

    # INVESTIGATION
    console.print("\n[bold cyan]Investigation Steps[/bold cyan]")

    investigation = item.get("investigation", [])

    if investigation:
        for number, step in enumerate(investigation, start=1):
            console.print(f"  [green]{number}.[/green] {step}")
    else:
        console.print("  [dim]No investigation steps defined.[/dim]")

    # FALSE POSITIVES
    console.print("\n[bold yellow]Possible False Positives[/bold yellow]")

    false_positives = item.get("false_positives", [])

    if false_positives:
        for fp in false_positives:
            console.print(f"  [yellow]•[/yellow] {fp}")
    else:
        console.print("  [dim]No false positives defined.[/dim]")

    # RESPONSE
    console.print("\n[bold red]Recommended Response[/bold red]")

    responses = item.get("response", [])

    if responses:
        for step in responses:
            console.print(f"  [red]•[/red] {step}")
    else:
        console.print("  [dim]No response steps defined.[/dim]")

    # NOTES
    console.print(
        Panel(
            item.get("notes", "N/A"),
            title="Notes",
            border_style="yellow",
        )
    )


def search_queries():
    keyword = Prompt.ask(
        "\n[bold cyan]Search keyword[/bold cyan]"
    ).strip().lower()

    results = []

    for item in QUERIES:
        mitre_id, mitre_name, mitre_tactic, _ = get_mitre_info(item)

        searchable = [
            item.get("name", ""),
            item.get("query", ""),
            item.get("description", ""),
            item.get("category", ""),
            item.get("log_source", ""),
            mitre_id,
            mitre_name,
            mitre_tactic,
        ]

        searchable.extend(item.get("keywords", []))

        if any(
            keyword in str(value).lower()
            for value in searchable
        ):
            results.append(item)

    if not results:
        console.print(
            "[bold yellow]No matching queries found.[/bold yellow]"
        )
        return

    table = Table(
        title=f"Search Results — {len(results)} match(es)",
        box=box.ROUNDED,
    )

    table.add_column("ID", style="cyan")
    table.add_column("Detection", style="green")
    table.add_column("MITRE", style="magenta")
    table.add_column("Severity")

    for item in results:
        mitre_id, _, _, _ = get_mitre_info(item)

        table.add_row(
            f"{item['number']:03}",
            item["name"],
            mitre_id,
            severity_markup(item.get("severity", "N/A")),
        )

    console.print(table)


def search_mitre():
    mitre_id = Prompt.ask(
        "\n[bold magenta]MITRE ATT&CK ID[/bold magenta]"
    ).strip().upper()

    results = []

    for item in QUERIES:
        current_id, _, _, _ = get_mitre_info(item)

        if current_id.upper() == mitre_id:
            results.append(item)

    if not results:
        console.print(
            f"[bold yellow]No detections mapped to {mitre_id}.[/bold yellow]"
        )
        return

    table = Table(
        title=f"MITRE ATT&CK — {mitre_id}",
        box=box.ROUNDED,
    )

    table.add_column("ID", style="cyan")
    table.add_column("Detection", style="green")
    table.add_column("Severity")

    for item in results:
        table.add_row(
            f"{item['number']:03}",
            item["name"],
            severity_markup(item.get("severity", "N/A")),
        )

    console.print(table)


def main():
    banner()
    loading_animation()

    while True:
        show_menu()

        choice = Prompt.ask(
            "\n[bold cyan]SnipTe$t@Splunk[/bold cyan] "
            "[green]>[/green]"
        ).strip().lower()

        if choice in ["exit", "quit", "q"]:
            console.print(
                "\n[bold cyan]Stay curious. Hunt threats.[/bold cyan]"
            )
            break

        elif choice == "search":
            search_queries()

        elif choice == "mitre":
            search_mitre()

        elif choice == "list":
            banner()
            continue

        elif choice.isdigit():
            number = int(choice)

            if 1 <= number <= len(QUERIES):
                show_query(number - 1)
            else:
                console.print(
                    f"[bold red]Choose a number from 1 to {len(QUERIES)}.[/bold red]"
                )

        else:
            console.print(
                "[bold red]Unknown command.[/bold red] "
                f"Use 1-{len(QUERIES)}, search, mitre, list, or exit."
            )

        console.input("\n[dim]Press ENTER to continue...[/dim]")
        banner()


if __name__ == "__main__":
    main()
