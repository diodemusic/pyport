import click
import socket
from datetime import datetime
import sys
import asyncio
import pyfiglet


class PortScannerError(Exception):
    pass


@click.command()
@click.option(
    "--t",
    prompt="Enter an IP adrress or hostname",
    help="Target to scan (ip or hostname).",
)
@click.option(
    "--p",
    prompt="Enter a ports list text file filename",
    help="Ports list text file filename.",
)
def scan(t: str, p: str) -> None:
    """Scan an IP's ports asynchronously."""
    c = 10

    try:
        target = socket.gethostbyname(t)
    except socket.gaierror as e:
        click.echo(click.style(f"Error resolving target: {t}: {e}", fg="red"))
        sys.exit(1)

    click.echo(click.style(pyfiglet.figlet_format("pyport", font="3-d"), fg="blue"))

    click.echo("-" * 50)
    click.echo(f"Scanning Target > {t}")
    click.echo(f"Scanning started at > {str(datetime.now())}")
    click.echo("-" * 50)
    click.echo("Please wait...\n")

    try:
        with open(p, "r") as f:
            ports = [int(line.strip()) for line in f if line.strip().isdigit()]

        asyncio.run(scan_ports(target, ports, c))

    except PortScannerError as e:
        click.echo(click.style(f"Error: {e}", fg="red"))
        sys.exit(1)
    except socket.gaierror as e:
        click.echo(click.style(f"Error: {e}", fg="red"))
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo("\nScan aborted by user.")
        sys.exit(0)
    except socket.error as e:
        click.echo(click.style(f"Error: {e}", fg="red"))
        sys.exit(1)
    except asyncio.CancelledError:
        click.echo("\nScan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        click.echo(click.style(f"Unexpected error: {e}", fg="red"))
        sys.exit(1)
    else:
        click.echo("\nScan complete.")


async def scan_port(target: str, port: int) -> None:
    """Scan a single port on the target asynchronously.

    Args:
        target (str): Target IP address or hostname.
        port (int): Port to scan.
    """
    try:
        _, writer = await asyncio.open_connection(target, port)

        service_name = socket.getservbyport(port, "tcp")
        click.echo(f"Port {port}: {service_name} > open")

        writer.close()

    except (socket.error, asyncio.TimeoutError):
        pass  # Port is not open
    except Exception as e:
        click.echo(click.style(f"Error scanning port: {port}: {e}", fg="red"))


async def scan_ports(target: str, ports: list, concurrency: int) -> None:
    """Scan multiple ports asynchronously.

    Args:
        target (str): Target IP address or hostname.
        ports (list): List of ports to scan.
        concurrency (int): Number of concurrent connections.
    """
    tasks = [scan_port(target, port) for port in ports]

    async with asyncio.Semaphore(concurrency):
        await asyncio.gather(*tasks)


if __name__ == "__main__":
    scan()
