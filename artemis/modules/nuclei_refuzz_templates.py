"""Cheap Nuclei templates for re-fuzzing a DAST finding while its PoC URL is
being shortened.

A DAST template carries a whole list of payloads (open-redirect-bypass: 106)
and, in multiple fuzzing mode, sends one request per payload. A re-fuzz of a
subset of parameters that does *not* contain the vulnerable one never matches,
so it goes through the whole list - ~106 requests, at one request per second
more than the re-fuzz timeout. The finding is already known to fire with one
particular payload, so the re-fuzz only needs that one: this module identifies
it from the finding and writes a copy of the template that carries only it.

Everything here works on the parsed template and never talks to Nuclei; the
callers in ``artemis/modules/nuclei.py`` run it.
"""

import os
import re
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

# Nuclei's default -fuzz-aggression; Artemis does not change it.
FUZZ_AGGRESSION_LEVEL = "low"
_AGGRESSION_LEVELS = {"low": ["low"], "medium": ["low", "medium"], "high": ["low", "medium", "high"]}

# A Nuclei expression ({{...}}) or an old-style payload marker (§name§).
_EXPRESSION = re.compile(r"\{\{.*?\}\}|§[^§]*§", re.DOTALL)
_INTERACTSH_URL = "{{interactsh-url}}"


class _Yaml12Loader(yaml.SafeLoader):
    """SafeLoader resolving scalars the YAML 1.2 way, as Nuclei (Go) does.

    PyYAML follows YAML 1.1, where e.g. ``yes``/``on`` are booleans and
    ``1:20`` is an integer. Loaded that way, a payload ``yes`` would come back
    from the dump as ``true`` - a different payload.
    """


_YAML_BOOL = "tag:yaml.org,2002:bool"
_YAML_INT = "tag:yaml.org,2002:int"
_Yaml12Loader.yaml_implicit_resolvers = {
    first: [(tag, regexp) for tag, regexp in resolvers if tag not in (_YAML_BOOL, _YAML_INT)]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
# What add_implicit_resolver() does, without its untyped call.
for _tag, _regexp, _first in (
    (_YAML_BOOL, re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), "tTfF"),
    (_YAML_INT, re.compile(r"^(?:[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+)$"), "-+0123456789"),
):
    for _character in _first:
        _Yaml12Loader.yaml_implicit_resolvers.setdefault(_character, []).append((_tag, _regexp))


def load_template(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        template = yaml.load(f, Loader=_Yaml12Loader)  # nosec - a safe loader
    if not isinstance(template, dict):
        raise ValueError(f"{path} is not a Nuclei template")
    return template


def write_template(template: Dict[str, Any], directory: str, name: str) -> str:
    """Write ``template`` to ``directory``. The copy is unsigned (the digest is
    a comment and does not survive), which Nuclei runs - with a warning - for
    HTTP templates."""
    path = os.path.join(directory, name + ".yaml")
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(template, f, sort_keys=False, allow_unicode=True, width=1 << 30)
    return path


def _http_requests(template: Dict[str, Any]) -> List[Dict[str, Any]]:
    requests = template.get("http") or template.get("requests") or []
    return [request for request in requests if isinstance(request, dict)]


def _fuzzing_requests(template: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [request for request in _http_requests(template) if request.get("fuzzing")]


def uses_interactsh_matchers(template: Dict[str, Any]) -> bool:
    """Whether the finding's evidence is an out-of-band interaction.

    The same test as Nuclei's ``interactsh.HasMatchers``: a matcher or
    extractor on an ``interactsh_*`` part or a DSL expression mentioning it.
    ``{{interactsh-url}}`` in a payload does not count - response-ssrf sends
    one, but its matchers check the HTTP response, so it is in-band. Neither
    does "oast" in a payload: open-redirect-bypass uses oast.me only as a
    canary in the Location header.
    """
    for request in _http_requests(template):
        for operator in (request.get("matchers") or []) + (request.get("extractors") or []):
            if not isinstance(operator, dict):
                continue
            if str(operator.get("part") or "").startswith("interactsh"):
                return True
            if any("interactsh" in str(expression).lower() for expression in operator.get("dsl") or []):
                return True
    return False


def _payload_entries(value: Any) -> Optional[List[str]]:
    """The payload values Nuclei iterates for one payload set, or None for a
    shape that is not narrowed (a wordlist file, non-string values)."""
    if isinstance(value, list):
        entries = value
    elif isinstance(value, dict):
        entries = []
        for level in _AGGRESSION_LEVELS[FUZZ_AGGRESSION_LEVEL]:
            entries.extend(value.get(level) or [])
    else:
        return None
    if not entries or not all(isinstance(entry, str) for entry in entries):
        return None
    return entries


def _skeleton(text: str, substitutions: Dict[str, str]) -> str:
    """A regex matching what ``text`` can evaluate to: literal parts as they
    are, ``{{name}}`` for a name in ``substitutions`` replaced with its regex,
    any other expression with anything."""
    pattern = []
    position = 0
    for expression in _EXPRESSION.finditer(text):
        pattern.append(re.escape(text[position : expression.start()]))
        inner = expression.group(0)[2:-2].strip() if expression.group(0).startswith("{{") else None
        pattern.append(substitutions.get(inner, ".*?") if inner is not None else ".*?")
        position = expression.end()
    pattern.append(re.escape(text[position:]))
    return "".join(pattern)


def _decodings(raw: str) -> Iterable[str]:
    # Nuclei leaves most characters raw in the query it builds, but encodes
    # some; try the value as it is and decoded.
    yield raw
    yield urllib.parse.unquote(raw)
    yield urllib.parse.unquote_plus(raw)


def _inserted_values(base_raw: str, fuzzed_raw: str) -> Iterable[str]:
    """What a fuzzing rule could have put into a value that was ``base_raw``
    and became ``fuzzed_raw``: the whole value (type replace) or the added
    part (postfix, prefix)."""
    for base, fuzzed in zip(_decodings(base_raw), _decodings(fuzzed_raw)):
        yield fuzzed
        if base and fuzzed.startswith(base):
            yield fuzzed[len(base) :]
        if base and fuzzed.endswith(base):
            yield fuzzed[: -len(base)]


def _value(raw_pair: str) -> str:
    return raw_pair.split("=", 1)[1] if "=" in raw_pair else ""


def payload_set(template: Dict[str, Any]) -> Optional[Tuple[str, List[str]]]:
    """The name and the entries of the one payload list a DAST template
    iterates, or None if it has another shape (no payloads, several lists
    combined by an attack type, a wordlist file)."""
    requests = _fuzzing_requests(template)
    if len(requests) != 1:
        return None
    payloads = requests[0].get("payloads") or {}
    if not isinstance(payloads, dict) or len(payloads) != 1:
        return None
    ((name, value),) = payloads.items()
    entries = _payload_entries(value)
    if entries is None:
        return None
    return str(name), entries


def find_matching_payloads(
    template: Dict[str, Any], aligned_pairs: Sequence[Tuple[str, str]]
) -> Optional[Tuple[str, List[str], List[str]]]:
    """Find the payload(s) a multiple-mode DAST finding fired with.

    ``aligned_pairs`` are the (base, matched-at) raw ``name=value`` pairs of
    the URL Nuclei fuzzed and of the matched-at URL. In multiple mode one
    request carries one payload in every parameter a fuzzing rule picked, so
    a payload fits if, for every changed parameter, some rule's ``fuzz``
    expression with that payload evaluates to the inserted value.

    Returns (payload set name, matching entries in template order, all
    entries), or None when this cannot be told - more than one payload set or
    request, a wordlist file, no changed parameter, nothing fits - in which
    case the caller re-fuzzes with the whole template. More than one entry may
    fit (``//oast.me`` and ``{{RootURL}}oast.me`` look the same once
    evaluated); keeping all of them only costs a request each.
    """
    found = payload_set(template)
    if found is None:
        return None
    name, entries = found
    request = _fuzzing_requests(template)[0]

    fuzz_expressions: List[str] = []
    for rule in request["fuzzing"]:
        if not isinstance(rule, dict) or not isinstance(rule.get("fuzz"), list):
            return None
        fuzz_expressions.extend(expression for expression in rule["fuzz"] if isinstance(expression, str))
    if not fuzz_expressions:
        return None

    # In multiple mode the changed parameters share a handful of distinct
    # (old value, new value) shapes - one per default value - so check each once.
    changed = sorted({(_value(base), _value(fuzzed)) for base, fuzzed in aligned_pairs if base != fuzzed})
    if not changed:
        return None

    matching = []
    for entry in entries:
        patterns = [
            re.compile(_skeleton(expression, {name: "(?:" + _skeleton(entry, {}) + ")"}), re.DOTALL)
            for expression in fuzz_expressions
        ]
        if all(
            any(pattern.fullmatch(inserted) for pattern in patterns for inserted in _inserted_values(base, fuzzed))
            for base, fuzzed in changed
        ):
            matching.append(entry)

    if not matching or len(matching) == len(entries):
        return None
    return name, matching, entries


def with_payloads(template: Dict[str, Any], name: str, entries: List[str]) -> Dict[str, Any]:
    """A copy of ``template`` whose payload set ``name`` holds only ``entries``."""
    result = dict(template)
    key = "http" if "http" in template else "requests"
    result[key] = []
    for request in _http_requests(template):
        if request.get("fuzzing") and name in (request.get("payloads") or {}):
            request = dict(request)
            request["payloads"] = {name: list(entries)}
        result[key].append(request)
    return result


def _reference(name: str) -> "re.Pattern[str]":
    return re.compile(r"\{\{\s*" + re.escape(name) + r"\s*\}\}")


def oob_canary_template(template: Dict[str, Any], entries: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
    """A copy of an out-of-band template that gives every fuzzed parameter
    an OAST URL of its own, so a callback tells which parameter it came from.

    Nuclei renders ``{{interactsh-url}}`` in a payload once per payload - in
    single mode as well as in multiple, every parameter of every request gets
    the same URL (and a template variable holding the URL, like
    blind-oast-polyglots' ``marker``, is one URL for the whole run). The
    ``fuzz`` expression, however, is rendered for each parameter separately.
    So the payload is moved into the expression: payload ``p`` and expression
    ``https://{{ssrf}}`` become the expression ``https://p``, with the URL
    variables replaced by their ``{{interactsh-url}}``. In multiple mode that
    is one request per payload, carrying a distinct URL in each parameter.

    ``entries`` picks the payloads (default: all). Only payloads that send an
    OAST URL are used - some templates also have in-band ones. A raw ``&``
    is fine: Nuclei does not encode it, so the segments after it become
    parameters of their own, and those that are the same in every parameter
    end up behind the first one - but the OAST URL differs, so it stays right
    behind its parameter, which is all the attribution needs. A raw ``#``
    goes out as it is, as part of the query.
    Returns None if no payload is left, or for a shape this cannot be done
    for: more than one payload set or fuzzing request, a payload used inside
    a DSL function.
    """
    requests = _fuzzing_requests(template)
    if len(requests) != 1:
        return None
    request = requests[0]
    payloads = request.get("payloads") or {}
    if not isinstance(payloads, dict) or len(payloads) != 1:
        return None
    ((name, value),) = payloads.items()
    all_entries = _payload_entries(value)
    if all_entries is None:
        return None

    url_variables: Dict[str, str] = {}
    for variables in (template.get("variables"), request.get("variables")):
        for variable, variable_value in (variables or {}).items():
            if isinstance(variable_value, str) and _INTERACTSH_URL in variable_value:
                url_variables[variable] = variable_value

    def inline(entry: str) -> str:
        for variable, variable_value in url_variables.items():
            entry = _reference(variable).sub(lambda _: variable_value, entry)
        return entry

    chosen: List[str] = []
    for entry in all_entries:
        if (entries is None or entry in entries) and entry not in chosen:
            if _INTERACTSH_URL in inline(entry):
                chosen.append(entry)
    if not chosen:
        return None

    reference = _reference(name)
    rules = []
    for rule in request["fuzzing"]:
        if not isinstance(rule, dict) or not isinstance(rule.get("fuzz"), list):
            return None
        expressions = []
        for expression in rule["fuzz"]:
            if not isinstance(expression, str):
                return None
            # The payload must be referenced as a whole ({{name}}), not
            # inside a DSL function such as {{url_encode(name)}}.
            other_expressions = [
                m.group(0) for m in _EXPRESSION.finditer(expression) if not reference.fullmatch(m.group(0))
            ]
            if any(re.search(r"\b" + re.escape(name) + r"\b", other) for other in other_expressions):
                return None
            if not reference.search(expression):
                return None
            for entry in chosen:
                expressions.append(reference.sub(lambda _: inline(entry), expression))
        rules.append(dict(rule, fuzz=expressions))

    canary = {key: item for key, item in request.items() if key not in ("payloads", "attack")}
    canary["fuzzing"] = rules
    result = dict(template)
    key = "http" if "http" in template else "requests"
    result[key] = [canary if item is request else item for item in _http_requests(template)]
    return result


def fuzz_value_count(template: Dict[str, Any]) -> int:
    """How many values the fuzzing rules send: requests per URL in multiple mode."""
    return sum(
        len(rule.get("fuzz") or [])
        for request in _fuzzing_requests(template)
        for rule in request["fuzzing"]
        if isinstance(rule, dict)
    )


def needs_interactsh(template: Dict[str, Any]) -> bool:
    """Whether running ``template`` makes Nuclei generate interactsh URLs -
    so a re-fuzz with it cannot use ``-ni``."""
    return _INTERACTSH_URL in yaml.safe_dump(template, allow_unicode=True, width=1 << 30)
