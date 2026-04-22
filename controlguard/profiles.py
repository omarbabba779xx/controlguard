from __future__ import annotations

from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def builtin_profiles() -> dict[str, Path]:
    root = _repo_root()
    profiles: dict[str, Path] = {
        "lab": root / "config" / "lab-profile.json",
    }
    profiles_dir = root / "config" / "profiles"
    if profiles_dir.exists():
        for profile_path in sorted(profiles_dir.glob("*.json")):
            profiles[profile_path.stem] = profile_path
    return profiles


def resolve_profile_path(config_path: str | None, profile_name: str | None) -> Path:
    if config_path:
        return Path(config_path)

    profiles = builtin_profiles()
    selected_profile = profile_name or "lab"
    try:
        return profiles[selected_profile]
    except KeyError as exc:
        available = ", ".join(sorted(profiles))
        raise ValueError(f"Unknown built-in profile '{selected_profile}'. Available profiles: {available}") from exc
