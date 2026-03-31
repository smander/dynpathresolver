"""Tests for Windows SimProcedures."""
import pytest

def test_loadlibrary_imports():
    from dynpathresolver.simprocedures.windows import DynLoadLibraryA, DynLoadLibraryW
    assert DynLoadLibraryA is not None
    assert DynLoadLibraryW is not None

def test_getprocaddress_imports():
    from dynpathresolver.simprocedures.windows import DynGetProcAddress
    assert DynGetProcAddress is not None

def test_loadlibrary_has_loaded_libraries():
    from dynpathresolver.simprocedures.windows import DynLoadLibraryA
    assert hasattr(DynLoadLibraryA, 'loaded_libraries')
    assert isinstance(DynLoadLibraryA.loaded_libraries, dict)

def test_loadlibrary_has_library_paths():
    from dynpathresolver.simprocedures.windows import DynLoadLibraryA
    assert hasattr(DynLoadLibraryA, 'library_paths')
    assert isinstance(DynLoadLibraryA.library_paths, list)

def test_getprocaddress_has_resolved_symbols():
    from dynpathresolver.simprocedures.windows import DynGetProcAddress
    assert hasattr(DynGetProcAddress, 'resolved_symbols')
    assert isinstance(DynGetProcAddress.resolved_symbols, dict)

def test_loadlibrary_reset():
    from dynpathresolver.simprocedures.windows import DynLoadLibraryA
    DynLoadLibraryA.loaded_libraries[0x1000] = "test"
    DynLoadLibraryA.library_paths.append("/test")
    DynLoadLibraryA.reset()
    assert DynLoadLibraryA.loaded_libraries == {}
    assert DynLoadLibraryA.library_paths == []
