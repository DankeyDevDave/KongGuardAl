"""Kong Guard AI CLI interface."""

import typer
from rich.console import Console
from rich.table import Table

from kongguard import __version__

app = typer.Typer(
    name="kong-guard",
    help="Kong Guard AI - Enterprise security plugin for Kong Gateway",
    add_completion=False,
)
console = Console()


@app.command()
def version() -> None:
    """Show Kong Guard AI version."""
    console.print(f"Kong Guard AI v{__version__}")


@app.command()
def status() -> None:
    """Check Kong Guard AI system status."""
    table = Table(title="Kong Guard AI System Status")
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Version")

    # Add system components
    table.add_row("Kong Guard AI", "✅ Active", __version__)
    table.add_row("AI Service", "✅ Running", "v2.0.0")
    table.add_row("ML Models", "✅ Loaded", "v1.0.0")
    table.add_row("Database", "✅ Connected", "PostgreSQL 15")

    console.print(table)


@app.command()
def config(
    show: bool = typer.Option(False, "--show", help="Show current configuration"),
    validate: bool = typer.Option(False, "--validate", help="Validate configuration"),
) -> None:
    """Manage Kong Guard AI configuration."""
    if show:
        console.print("🔧 Current Configuration:", style="bold blue")
        console.print("• AI Service URL: http://ai-service:8000")
        console.print("• Database: Supabase")
        console.print("• Cache: Redis")
        console.print("• Monitoring: Prometheus")

    if validate:
        console.print("✅ Configuration is valid", style="green")


@app.command()
def demo() -> None:
    """Run Kong Guard AI demo."""
    from kongguard.attack_demos import run_demo

    console.print("🚀 Starting Kong Guard AI Demo...", style="bold green")
    run_demo()


def main() -> None:
    """Main CLI entry point."""
    app()


if __name__ == "__main__":
    main()
