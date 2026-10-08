"""Exceptions shared by the core, the helper and the clients. Messages are meant for the user."""

from __future__ import annotations


class RallError(Exception):
    """Base class: the message is meant for the user."""


class NotPermitted(RallError):
    """The operation needs administrator rights (root, or the helper started through pkexec)."""


class NotSupported(RallError):
    """The filesystem, the disk or the installed tools can't do this."""


class ToolMissing(NotSupported):
    """A program this operation needs isn't installed."""


class UnsafeOperation(RallError):
    """A destructive operation was refused (disk in use, recovering onto the source, missing confirmation, ...)."""


class FormatError(RallError):
    """On-disk structures are damaged or aren't what they claim to be (a parser gave up)."""


class ScanError(RallError):
    """A scan file is missing, damaged or from another version."""


class ServiceError(RallError):
    """The helper could not be reached, or it reported an error."""


class Cancelled(RallError):
    """A job was cancelled by the user."""


ERROR_TYPES = {cls.__name__: cls for cls in (RallError, NotPermitted, NotSupported, ToolMissing, UnsafeOperation,
                                               FormatError, ScanError, ServiceError, Cancelled)}
