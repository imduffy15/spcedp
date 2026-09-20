"""Package metadata and advertised imports."""

import spcedp


def test_version_is_a_nonempty_string() -> None:
    assert isinstance(spcedp.__version__, str)
    assert spcedp.__version__


def test_public_names_are_importable_and_unique() -> None:
    assert len(spcedp.__all__) == len(set(spcedp.__all__))
    for name in spcedp.__all__:
        assert hasattr(spcedp, name), name
