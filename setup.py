"""Include the established scanners in the wheel instead of assuming a checkout."""
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent


def copy_runtime_assets(destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")
    shutil.copy2(ROOT / "scan_all.py", destination / "scan_all.py")
    shutil.copytree(ROOT / "tools", destination / "tools", dirs_exist_ok=True, ignore=ignore)
    for skill in (ROOT / "skills").glob("detecting-*"):
        if skill.is_dir():
            shutil.copytree(skill, destination / "skills" / skill.name, dirs_exist_ok=True, ignore=ignore)


if __name__ == "__main__":
    from setuptools import setup
    from setuptools.command.build_py import build_py

    class BuildWithRuntime(build_py):
        def run(self):
            super().run()
            copy_runtime_assets(Path(self.build_lib) / "gxsec" / "_assets")

    setup(cmdclass={"build_py": BuildWithRuntime})
