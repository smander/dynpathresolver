"""Tests for DynPathResolver v2 parameters."""
import pytest

def test_v2_default_parameters():
    """Test v2 parameters have correct defaults."""
    from dynpathresolver import DynPathResolver
    dpr = DynPathResolver()
    assert dpr.directed_mode == False
    assert dpr.platform == 'auto'
    assert dpr.path_predictor == 'heuristic'
    assert dpr.handle_unpacking == False

def test_v2_custom_parameters():
    """Test v2 parameters can be customized."""
    from dynpathresolver import DynPathResolver
    dpr = DynPathResolver(
        directed_mode=True,
        platform='windows',
        path_predictor='none',
        handle_unpacking=True,
    )
    assert dpr.directed_mode == True
    assert dpr.platform == 'windows'
    assert dpr.path_predictor == 'none'
    assert dpr.handle_unpacking == True

def test_invalid_platform_raises():
    """Test invalid platform raises ValueError."""
    from dynpathresolver import DynPathResolver
    with pytest.raises(ValueError, match="Unknown platform"):
        DynPathResolver(platform='macos')

def test_invalid_predictor_raises():
    """Test invalid predictor raises ValueError."""
    from dynpathresolver import DynPathResolver
    with pytest.raises(ValueError, match="Unknown path_predictor"):
        DynPathResolver(path_predictor='ml')
