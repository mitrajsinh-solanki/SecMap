"""
SecMap Nmap Execution Engine
Handles safe subprocess execution of Nmap without shell expansion.
Phase 3 & Phase 4 implementation.
"""

from dataclasses import dataclass
import subprocess
from secmap_core.cli.arguments import ScanArguments
from secmap_core.parser import ScanResult, parse_nmap_xml


class NmapExecutionError(RuntimeError):
    """Raised when Nmap binary is missing or cannot be executed."""

    pass


@dataclass
class NmapResult:
    """Dataclass storing the output and exit status of an Nmap process execution."""

    command: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def success(self) -> bool:
        """Returns True if the process completed with returncode 0."""
        return self.returncode == 0


class NmapExecutor:
    """Manages the execution of Nmap process calls."""

    def __init__(self, executable: str = "nmap"):
        self.executable = executable

    def build_command(self, nmap_args: list[str], targets: list[str]) -> list[str]:
        """
        Construct argument list for subprocess execution.

        Args:
            nmap_args (list[str]): Parsed Nmap option flags.
            targets (list[str]): Target IPs, hostnames, or CIDR blocks.

        Returns:
            list[str]: Array-based command list starting with the executable.
        """
        return [self.executable] + list(nmap_args) + list(targets)

    def execute(self, scan_args: ScanArguments) -> NmapResult:
        """
        Execute Nmap via subprocess.run using safe array arguments (shell=False).

        Args:
            scan_args (ScanArguments): Parsed CLI scan parameters.

        Returns:
            NmapResult: Captured execution data.

        Raises:
            NmapExecutionError: If Nmap binary is missing or process creation fails.
        """
        command = self.build_command(scan_args.nmap_args, scan_args.targets)

        try:
            completed_process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                shell=False,
                check=False,
                stdin=subprocess.DEVNULL,
            )

            return NmapResult(
                command=command,
                returncode=completed_process.returncode,
                stdout=completed_process.stdout or "",
                stderr=completed_process.stderr or "",
            )

        except FileNotFoundError:
            raise NmapExecutionError(
                "SecMap Error: Nmap executable was not found. Install Nmap or verify that it is available in PATH."
            )
        except KeyboardInterrupt:
            raise NmapExecutionError("SecMap Error: Scan cancelled by user.")
        except Exception as e:
            raise NmapExecutionError(f"SecMap Error: Failed to execute Nmap driver: {str(e)}")

    def execute_xml(self, scan_args: ScanArguments) -> tuple[NmapResult, ScanResult]:
        """
        Execute Nmap forcing XML output via stdout stream (-oX -) and parse into a ScanResult model.

        Args:
            scan_args (ScanArguments): Parsed CLI scan parameters.

        Returns:
            tuple[NmapResult, ScanResult]: Raw execution result and parsed data model.
        """
        # Inject -oX - before targets
        xml_cmd_args = list(scan_args.nmap_args) + ["-oX", "-"]
        command = self.build_command(xml_cmd_args, scan_args.targets)

        try:
            completed_process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                shell=False,
                check=False,
                stdin=subprocess.DEVNULL,
            )

            result = NmapResult(
                command=command,
                returncode=completed_process.returncode,
                stdout=completed_process.stdout or "",
                stderr=completed_process.stderr or "",
            )

            if not result.stdout and result.returncode != 0:
                err_msg = result.stderr.strip() if result.stderr else f"Exited with return code {result.returncode}"
                raise NmapExecutionError(f"SecMap Error: Nmap scan failed: {err_msg}")

            scan_result = parse_nmap_xml(result.stdout)
            return result, scan_result

        except FileNotFoundError:
            raise NmapExecutionError(
                "SecMap Error: Nmap executable was not found. Install Nmap or verify that it is available in PATH."
            )
        except KeyboardInterrupt:
            raise NmapExecutionError("SecMap Error: Scan cancelled by user.")
        except NmapExecutionError:
            raise
        except Exception as e:
            raise NmapExecutionError(f"SecMap Error: Failed to execute Nmap XML scan: {str(e)}")
