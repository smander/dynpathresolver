"""Platform detection for DynPathResolver."""
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import angr

log = logging.getLogger(__name__)


class PlatformDetector:
    """Detect target platform from binary format."""

    @staticmethod
    def detect(project: "angr.Project") -> str:
        """
        Detect platform from the loaded binary.

        Returns 'linux' or 'windows'
        """
        main_obj = project.loader.main_object
        class_name = main_obj.__class__.__name__

        # Check class name first
        if class_name == 'PE':
            log.debug("Detected Windows from PE format")
            return 'windows'
        elif class_name == 'ELF':
            log.debug("Detected Linux from ELF format")
            return 'linux'

        # Check os attribute
        if hasattr(main_obj, 'os') and main_obj.os:
            os_name = str(main_obj.os).lower()
            if 'windows' in os_name:
                return 'windows'
            elif 'linux' in os_name:
                return 'linux'

        # Default to Linux
        log.debug("Unknown format, defaulting to Linux")
        return 'linux'
