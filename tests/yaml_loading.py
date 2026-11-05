# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Read a YAML file as written, refusing what PyYAML would silently fold.

PyYAML keeps the last of two equal keys and retypes a bare ``on``,
``off``, ``no``, ``null`` or number. The contract tests look their
entries up by the key written, so a document is read here with both
loaders and must say the same thing twice before a test sees it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import yaml

ROOT = Path(__file__).resolve().parent.parent


def read_text(path: str) -> str:
    """Return the text of ``path``, relative to the repository root."""
    return (ROOT / path).read_text(encoding="utf-8")


def reject_duplicate_keys(node: object) -> None:
    """Fail when a mapping under ``node`` writes one key twice.

    PyYAML keeps the last of two equal keys and drops the first without
    a word, so a job, an input or an output written twice would reach
    the tests as one entry, and the lookups by key could not tell.
    Every lookup therefore starts here. A workflow's keys are scalars,
    compared by their text, as ``yaml.BaseLoader`` reads them: a bare
    ``on`` and a quoted ``"on"`` are one key. ``reject_retyped_keys``
    then holds every key but ``on`` to being that text once loaded.
    """
    if isinstance(node, yaml.MappingNode):
        seen: set[str] = set()
        pairs = cast("list[tuple[object, object]]", node.value)
        for key_node, value_node in pairs:
            if isinstance(key_node, yaml.ScalarNode):
                key = key_node.value
                if key in seen:
                    raise yaml.constructor.ConstructorError(
                        "while constructing a mapping",
                        node.start_mark,
                        f"found duplicate key {key!r}",
                        key_node.start_mark,
                    )
                seen.add(key)
            reject_duplicate_keys(key_node)
            reject_duplicate_keys(value_node)
    elif isinstance(node, yaml.SequenceNode):
        for child in cast("list[object]", node.value):
            reject_duplicate_keys(child)


def reject_retyped_keys(
    base: object, safe: object, path: tuple[str, ...] = ()
) -> None:
    """Fail where ``yaml.SafeLoader`` reads a mapping key as not its text.

    ``base`` is a document as ``yaml.BaseLoader`` reads it, every key
    the string written, and ``safe`` the same document as
    ``yaml.SafeLoader`` reads it, where ``off``, ``no``, ``null``, ``~``
    and a bare number become a boolean, ``None`` or an integer. The
    tests look jobs, inputs and outputs up by their written name, so a
    retyped key would hide its entry from them without a word, and two
    spellings of one value would fold into one entry. The keys of the
    two readings must therefore agree at every level, with the
    workflow's top-level ``on``, which ``load_workflow`` renames back,
    the one tolerated difference. The failure names the key's path.
    """
    if isinstance(base, dict):
        base_map = cast("dict[str, object]", base)
        safe_map = (
            cast("dict[object, object]", safe)
            if isinstance(safe, dict)
            else {}
        )
        safe_keys = list(safe_map)
        for index, key in enumerate(base_map):
            where = ".".join([*path, key])
            if index >= len(safe_keys):
                raise AssertionError(
                    f"PyYAML folds key {key!r} at {where} into an earlier"
                    " key of the same mapping; quote it"
                )
            typed = safe_keys[index]
            if typed != key and not (
                not path and key == "on" and typed is True
            ):
                raise AssertionError(
                    f"PyYAML reads key {key!r} at {where} as {typed!r},"
                    " not as its text; quote it"
                )
        for key, typed in zip(base_map, safe_keys, strict=True):
            reject_retyped_keys(base_map[key], safe_map[typed], (*path, key))
    elif isinstance(base, list):
        safe_list = (
            cast("list[object]", safe) if isinstance(safe, list) else []
        )
        for index, child in enumerate(cast("list[object]", base)):
            reject_retyped_keys(child, safe_list[index], (*path, f"{index}"))


Reader = type[yaml.BaseLoader] | type[yaml.SafeLoader]


def read_with(reader: Reader, document: str) -> object:
    """Return the one document in ``document`` as ``reader`` reads it."""
    loader = reader(document)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def parse_yaml(document: str) -> Any:  # noqa: ANN401  # a YAML document
    """Parse ``document`` as ``safe_load`` does, holding its keys to its text.

    Fails on a mapping key written twice, and on a key that PyYAML
    would read as anything but the string written, ``on`` at the top
    level aside.
    """
    loader = yaml.SafeLoader(document)
    try:
        reject_duplicate_keys(loader.get_single_node())
    finally:
        loader.dispose()
    loaded = read_with(yaml.SafeLoader, document)
    reject_retyped_keys(read_with(yaml.BaseLoader, document), loaded)
    return loaded


def load_yaml(path: str) -> Any:  # noqa: ANN401  # a YAML document
    """Parse the YAML file at ``path``, relative to the repository root."""
    return parse_yaml(read_text(path))
