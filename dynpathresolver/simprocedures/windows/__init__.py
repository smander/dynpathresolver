"""Windows SimProcedures for LoadLibrary/GetProcAddress."""
from .loadlibrary import DynLoadLibraryA, DynLoadLibraryW
from .getprocaddress import DynGetProcAddress

__all__ = ['DynLoadLibraryA', 'DynLoadLibraryW', 'DynGetProcAddress']
