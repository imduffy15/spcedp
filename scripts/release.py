"""Check Python distributions and publish them with a matching Git tag."""

import os
import subprocess
import sys
import tomllib
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]


def check() -> tuple[str, list[Path]]:
    """Require the declared version and both installable distribution formats."""
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    tag = os.environ.get("RELEASE_TAG", f"v{version}")
    if tag != f"v{version}":
        raise ValueError(f"Tag {tag!r} does not match version {version}")
    wheel = ROOT / f"dist/spcedp-{version}-py3-none-any.whl"
    sdist = ROOT / f"dist/spcedp-{version}.tar.gz"
    if not wheel.is_file() or not sdist.is_file():
        raise ValueError("Build the wheel and source distribution first")
    with ZipFile(wheel) as archive:
        if archive.testzip() is not None or "spcedp/py.typed" not in archive.namelist():
            raise ValueError("Wheel is corrupt or missing its typing marker")
    return tag, [wheel, sdist]


def main() -> None:
    tag, artifacts = check()
    if sys.argv[1] == "check":
        print(tag)
        return
    if sys.argv[1] != "publish" or "RELEASE_TAG" not in os.environ:
        raise ValueError("Use check, or publish with an explicit RELEASE_TAG")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT)
    tagged = subprocess.check_output(["git", "rev-parse", f"{tag}^{{commit}}"], cwd=ROOT)
    if head != tagged:
        raise ValueError("Release tag does not point to this checkout")
    subprocess.run(
        ["gh", "release", "create", tag, *map(str, artifacts), "--verify-tag", "--generate-notes"],
        cwd=ROOT,
        check=True,
    )


if __name__ == "__main__":
    main()
