import logging
import mimetypes
import re
import urllib.parse
from collections.abc import Sequence
from pathlib import Path
from typing import NamedTuple, Union

from werkzeug.security import safe_join

from mitmproxy import ctx, exceptions, flowfilter, http, version
from mitmproxy.utils.spec import parse_spec

replacement_group_regex = r'\${[0-9]+}'

class MapLocalSpec(NamedTuple):
    matches: flowfilter.TFilter
    regex: str
    local_path: Path

class MapLocalCapturingSpec(NamedTuple):
    matches: flowfilter.TFilter
    regex: str
    replacement: str
    replacement_groups: dict


def parse_map_local_spec(option: str) -> Union[MapLocalSpec,MapLocalCapturingSpec]:
    filter, regex, replacement = parse_spec(option)

    r_matches = re.findall(replacement_group_regex, replacement)

    try:
        re.compile(regex)
    except re.error as e:
        raise ValueError(f"Invalid regular expression {regex!r} ({e})")

    if len(r_matches) == 0:
        try:
            path = Path(replacement).expanduser().resolve(strict=True)
        except FileNotFoundError as e:
            raise ValueError(f"Invalid file path: {replacement} ({e})")
        return MapLocalSpec(filter, regex, path)
    else:
        replacement_groups = {}
        for r_group in r_matches:
            try:
                # for replacement ${1}, we save group index 0
                r_group_idx = int(r_group[2:-1]) - 1
                replacement_groups[r_group_idx] = r_group
            except re.error as e:
                raise ValueError(f"Invalid value on replacement group: {r_group} ({e})")
        return MapLocalCapturingSpec(filter, regex, replacement, replacement_groups)


def _safe_path_join(root: Path, untrusted: str) -> Path:
    """Join a Path element with an untrusted str.

    This is a convenience wrapper for werkzeug's safe_join,
    raising a ValueError if the path is malformed."""
    untrusted_parts = Path(untrusted).parts
    joined = safe_join(root.as_posix(), *untrusted_parts)
    if joined is None:
        raise ValueError("Untrusted paths.")
    return Path(joined)


def file_candidates(url: str, spec: Union[MapLocalSpec,MapLocalCapturingSpec]) -> list[Path]:
    """
    Get all potential file candidates given a URL and a mapping spec ordered by preference.
    This function already assumes that the spec regex matches the URL.
    """
    if getattr(spec, 'local_path', None):
        return file_candidates_basic(url, spec)
    else:
        return file_candidates_capturing(url, spec)


def file_candidates_basic(url: str, spec: MapLocalSpec) -> list[Path]:
    m = re.search(spec.regex, url)
    assert m
    if m.groups():
        suffix = m.group(1)
    else:
        suffix = re.split(spec.regex, url, maxsplit=1)[1]
        suffix = suffix.split("?")[0]  # remove query string
        suffix = suffix.strip("/")

    if suffix:
        decoded_suffix = urllib.parse.unquote(suffix)
        suffix_candidates = [decoded_suffix, f"{decoded_suffix}/index.html"]

        escaped_suffix = re.sub(r"[^0-9a-zA-Z\-_.=(),/]", "_", decoded_suffix)
        if decoded_suffix != escaped_suffix:
            suffix_candidates.extend([escaped_suffix, f"{escaped_suffix}/index.html"])
        try:
            return [_safe_path_join(spec.local_path, x) for x in suffix_candidates]
        except ValueError:
            return []
    else:
        return [spec.local_path / "index.html"]


def file_candidates_capturing(url: str, spec: MapLocalCapturingSpec) -> list[Path]:
    url_matches = re.findall(spec.regex, url)
    replaced_local_path = spec.replacement

    if url_matches is None:
        ctx.log.warn(f"No capturing groups result for: {url}. Maybe there is an error on capturing regex? : {spec.regex}")
        return []
    else:
        matchIdx = 0
        if type(url_matches[0]) is tuple:
            url_matches = url_matches[0]
        for match in url_matches:
            replaced_local_path = replaced_local_path.replace(spec.replacement_groups[matchIdx], match)
            matchIdx += 1

    try:
        path = Path(replaced_local_path).expanduser().resolve(strict=True)
    except FileNotFoundError as e:
        return []

    return [path, path / "index.html"]


class MapLocal:
    def __init__(self):
        self.replacements: list[MapLocalSpec] = []

    def load(self, loader):
        loader.add_option(
            "map_local",
            Sequence[str],
            [],
            """
            Map remote resources to a local file using a pattern of the form
            "[/flow-filter]/url-regex/file-or-directory-path", where the
            separator can be any character.
            """,
        )

    def configure(self, updated):
        if "map_local" in updated:
            self.replacements = []
            for option in ctx.options.map_local:
                try:
                    spec = parse_map_local_spec(option)
                except ValueError as e:
                    raise exceptions.OptionsError(
                        f"Cannot parse map_local option {option}: {e}"
                    ) from e

                self.replacements.append(spec)

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.response or flow.error or not flow.live:
            return

        url = flow.request.pretty_url

        all_candidates = []
        for spec in self.replacements:
            if spec.matches(flow) and re.search(spec.regex, url):
                if getattr(spec, 'local_path', None) and spec.local_path.is_file():
                    candidates = [spec.local_path]
                else:
                    candidates = file_candidates(url, spec)
                all_candidates.extend(candidates)

                local_file = None
                for candidate in candidates:
                    if candidate.is_file():
                        local_file = candidate
                        break

                if local_file:
                    headers = {"Server": version.MITMPROXY}
                    mimetype = mimetypes.guess_type(str(local_file))[0]
                    if mimetype:
                        headers["Content-Type"] = mimetype

                    try:
                        contents = local_file.read_bytes()
                    except OSError as e:
                        logging.warning(f"Could not read file: {e}")
                        continue

                    flow.response = http.Response.make(200, contents, headers)
                    # only set flow.response once, for the first matching rule
                    return
        if all_candidates:
            flow.response = http.Response.make(404)
            logging.info(
                f"None of the local file candidates exist: {', '.join(str(x) for x in all_candidates)}"
            )
