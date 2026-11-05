"""Bounded source context proposals; never verification or suppression authority.

Only inventory-selected, hash-matching files are read. XML is parsed without
DTD/entity resolution; no inspected code, expressions, or configuration execute.
"""
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
import re
from xml.parsers import expat

from .models import content_hash
from .source import reject_reparse_path


ANALYZER = "gxsec-contextual/1"
MAX_FILES = 8192
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_XML_DEPTH = 96
MAX_XML_NODES = 12000
MAX_TOTAL_XML_NODES = 50000
MAX_BINDING_BYTES = 16384
MAX_CALLS = 4096
MAX_INCLUDE_DEPTH = 32
MAX_INDEX_STEPS = 200000
MAX_REACHABILITY_ITEMS = 200000
_SUB = re.compile(r"\$\{([^{}]+)\}")
_BOUND = re.compile(r"#\{[^{}]+\}")
_STATEMENTS = {"select", "insert", "update", "delete"}
_BRANCHES = {"if", "choose", "when", "otherwise", "where", "trim", "set", "foreach"}
_SQL_NODES = _STATEMENTS | _BRANCHES | {"sql", "bind", "selectKey"}


@dataclass(eq=False)
class _Node:
    tag: str
    attrs: dict
    line: int
    end: int = 0
    parts: list = field(default_factory=list)
    column: int = 0


class _Rejected(ValueError):
    pass


def _parse_xml(text, *, node_budget=MAX_XML_NODES):
    """Keep real element scope and source lines without accepting entity input."""
    parser = expat.ParserCreate()
    stack, roots, comments = [], [], []
    count = 0

    def start(tag, attrs):
        nonlocal count
        count += 1
        if len(stack) >= MAX_XML_DEPTH or count > min(MAX_XML_NODES, node_budget):
            raise _Rejected("xml_resource_limit")
        node = _Node(tag, attrs, parser.CurrentLineNumber, column=parser.CurrentColumnNumber)
        (stack[-1].parts if stack else roots).append(node)
        stack.append(node)

    def end(tag):
        stack.pop().end = parser.CurrentLineNumber

    def data(value):
        if stack and value:
            parts = stack[-1].parts
            if parts and isinstance(parts[-1], tuple):
                prior, line = parts[-1]
                parts[-1] = (prior + value, line)
            else:
                parts.append((value, parser.CurrentLineNumber))

    def doctype(name, sysid, pubid, internal):
        if internal:
            raise _Rejected("xml_internal_subset_rejected")

    def entity(*args):
        raise _Rejected("xml_entity_rejected")

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = data
    def comment(value):
        start_line, start_column = parser.CurrentLineNumber, parser.CurrentColumnNumber
        end_line = start_line + value.count("\n")
        end_column = (len(value.rsplit("\n", 1)[-1]) + 3 if end_line != start_line
                      else start_column + len(value) + 7)
        comments.append((start_line, end_line, start_column, end_column))

    parser.CommentHandler = comment
    parser.StartDoctypeDeclHandler = doctype
    parser.EntityDeclHandler = entity
    parser.ExternalEntityRefHandler = lambda *args: 0
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        parser.Parse(text, True)
    except expat.ExpatError as exc:
        raise _Rejected("xml_malformed_or_entity_rejected") from exc
    if len(roots) != 1:
        raise _Rejected("xml_root_unresolved")
    return roots[0], comments, count


def _selected_source(source, inventory):
    texts, digests, errors = {}, {}, {}
    global_errors = []
    if isinstance(inventory, dict) and inventory.get("errors"):
        # The collector may omit unreadable files or whole reparse directories
        # from its entries. Do not copy raw paths/messages or infer completeness.
        global_errors.append("upstream_inventory_incomplete")
    try:
        root = reject_reparse_path(source).resolve(strict=True)
        if not root.is_dir():
            raise ValueError
    except (OSError, ValueError):
        return texts, digests, errors, ["source_root_rejected"]
    entries = inventory.get("inventory", []) if isinstance(inventory, dict) else inventory
    if not isinstance(entries, list):
        return texts, digests, errors, ["inventory_invalid"]
    seen, total, selected = set(), 0, 0
    for item in entries:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            global_errors.append("inventory_entry_invalid")
            continue
        name = item["path"].replace("\\", "/")
        if PurePosixPath(name).suffix.lower() not in {".xml", ".java", ".kt", ".js", ".jsx", ".ts", ".tsx", ".vue", ".html"}:
            continue
        if name in seen:
            errors[name] = "inventory_duplicate_path"
            texts.pop(name, None)
            continue
        seen.add(name)
        selected += 1
        if selected > MAX_FILES:
            global_errors.append("source_file_count_limit")
            break
        try:
            parts = PurePosixPath(name)
            if parts.is_absolute() or ".." in parts.parts or ":" in name or "\x00" in name:
                raise _Rejected("source_path_rejected")
            path = reject_reparse_path(root / name).resolve(strict=True)
            if not path.is_relative_to(root) or not path.is_file():
                raise _Rejected("source_path_rejected")
            if path.stat().st_size > MAX_FILE_BYTES:
                raise _Rejected("source_file_size_limit")
            with path.open("rb") as handle:
                raw = handle.read(MAX_FILE_BYTES + 1)
            if len(raw) > MAX_FILE_BYTES or total + len(raw) > MAX_TOTAL_BYTES:
                raise _Rejected("source_total_size_limit")
            total += len(raw)
            digest = hashlib.sha256(raw).hexdigest()
            if not item.get("hash") or digest != item["hash"]:
                raise _Rejected("source_hash_mismatch_or_missing")
            texts[name] = raw.decode("utf-8-sig")
            digests[name] = digest
        except _Rejected as exc:
            errors[name] = str(exc)
        except (OSError, ValueError, UnicodeError):
            errors[name] = "source_unreadable_or_path_rejected"
    return texts, digests, errors, sorted(set(global_errors))


def _evidence(kind, path, line, **extra):
    return {"kind": kind, "location": {"path": path, "line": line}, **extra}


def _context():
    return {
        "schema_version": 1, "analyzer": ANALYZER,
        "classification": "unsupported-context", "proposal": "needs_review",
        "evidence_for": [], "evidence_against": [], "unresolved": [],
        "instances": [], "limitations": [
            "Static context is a proposal and does not grant verification or approval.",
            "Deployment, attacker control, guards and runtime behavior are not established.",
        ], "binding_digest": "",
    }


def _family(finding):
    value = " ".join(str(finding.get(key, "")) for key in ("rule_id", "semantic_rule_id", "category" )).lower()
    if re.search(r"sql|sqli|jpql|mybatis", value):
        return "sql"
    if re.search(r"xss|cross.site.scripting|unsafe.html|v-html|innerhtml", value):
        return "html"
    return "unsupported"


def _configuration_substitution(root, text, line):
    """Recognize a finite configuration location, never an entire document.

    A line must intersect one ancestor chain with an explicitly supported leaf.
    Sibling/custom nodes on that line are ambiguous without candidate columns.
    """
    supported = {
        ("Configuration", "Properties", "Property"): {"#text"},
        ("Configuration", "Appenders", "Console", "PatternLayout"): {"pattern"},
        ("Configuration", "Appenders", "RollingFile"): {"fileName", "filePattern"},
        ("Configuration", "Appenders", "RollingFile", "PatternLayout"): {"pattern"},
        ("Configuration", "Appenders", "RollingFile", "DefaultRolloverStrategy", "Delete"): {"basePath"},
        ("configuration", "properties", "property"): {"value"},
    }
    active, pending = [], [(root, ())]
    while pending:
        node, ancestors = pending.pop()
        if node.line <= line <= node.end:
            chain = ancestors + (node,)
            active.append(chain)
            pending.extend((part, chain) for part in node.parts if isinstance(part, _Node))
    chain = max(active, key=len, default=())
    allowed = supported.get(tuple(node.tag for node in chain))
    if not allowed or any(chain[:len(other)] != other for other in active):
        return False
    node = chain[-1]
    locations = []
    # Expat's start column disambiguates nested tags sharing one source line.
    lines = text.splitlines(keepends=True)
    opening = re.match(r'''<(?:[^'"<>]|"[^"]*"|'[^']*')*>''',
                       "".join(lines[node.line - 1:])[node.column:])
    if not opening:
        return False
    for attr in re.finditer(r'''([^\s=<>/]+)\s*=\s*(["'])(.*?)\2''', opening[0], re.DOTALL):
        for token in _SUB.finditer(attr[3]):
            token_line = node.line + opening[0][:attr.start(3) + token.start()].count("\n")
            if token_line == line:
                locations.append(attr[1])
    for part in node.parts:
        if isinstance(part, tuple):
            value, start = part
            locations.extend("#text" for token in _SUB.finditer(value)
                             if start + value[:token.start()].count("\n") == line)
    # The finding has no token column: another substitution in an ancestor,
    # comment or adjacent text on this line cannot inherit the leaf's evidence.
    return (bool(locations) and len(_SUB.findall(lines[line - 1])) == len(locations)
            and all(location in allowed for location in locations))


class _Mappers:
    def __init__(self, texts, errors, global_errors):
        self.documents, self.fragments, self.statements = {}, {}, []
        self.errors = dict(errors)
        self.global_errors = list(global_errors)
        self.steps = 0
        self.index_steps = self.reachability_items = 0
        self._include_cache, self._reachability_cache = {}, {}
        remaining_nodes = MAX_TOTAL_XML_NODES
        for path, text in texts.items():
            if not path.lower().endswith(".xml"):
                continue
            try:
                root, comments, node_count = _parse_xml(text, node_budget=remaining_nodes)
                remaining_nodes -= node_count
                self.documents[path] = (root, comments)
                if root.tag != "mapper":
                    continue
                namespace = root.attrs.get("namespace", "")
                if not namespace or _SUB.search(namespace):
                    self.errors[path] = "mapper_namespace_unresolved"
                    continue
                for node in root.parts:
                    if not isinstance(node, _Node):
                        continue
                    if node.tag == "sql":
                        key = self._key(namespace, node.attrs.get("id", ""))
                        self.fragments.setdefault(key, []).append((path, namespace, node))
                    elif node.tag in _STATEMENTS:
                        self.statements.append((path, namespace, node))
            except _Rejected as exc:
                self.errors[path] = str(exc)

    @staticmethod
    def _key(namespace, name):
        return name if "." in name else namespace + "." + name

    @staticmethod
    def _substitute(value, env):
        # Replaces known static properties only. Unknown expressions are never
        # evaluated and remain explicit runtime/unknown tokens.
        pieces, cursor, length = [], 0, 0
        for match in _SUB.finditer(value):
            prefix = value[cursor:match.start()]
            replacement = env.get(match[1], match[0])
            length += len(prefix) + len(replacement)
            if length > MAX_BINDING_BYTES:
                raise _Rejected("binding_expansion_limit")
            pieces.extend((prefix, replacement))
            cursor = match.end()
        if length + len(value) - cursor > MAX_BINDING_BYTES:
            raise _Rejected("binding_expansion_limit")
        return "".join(pieces) + value[cursor:]

    def _index_step(self):
        self.index_steps += 1
        if self.index_steps > MAX_INDEX_STEPS:
            raise _Rejected("include_index_resource_limit")

    def _physical_includes(self, node):
        if node in self._include_cache:
            return self._include_cache[node]
        includes, pending = [], [node]
        while pending:
            self._index_step()
            current = pending.pop()
            if current.tag == "include":
                includes.append(current)
            else:
                pending.extend(part for part in current.parts if isinstance(part, _Node))
        self._include_cache[node] = includes
        return includes

    def _reachable(self, namespace, node, stack=()):
        """Cache only physical XML reachability; never evaluate property/OGNL values.

        Unknown dynamic refs retain every possible caller as a candidate. Actual
        expansion still checks each selected caller with its own property scope.
        """
        key = (namespace, node)
        if key in self._reachability_cache:
            return self._reachability_cache[key]
        if key in stack:
            return frozenset(), True
        if len(stack) > MAX_INCLUDE_DEPTH:
            return frozenset(), True
        reachable, unknown = set(), False
        try:
            self._index_step()
            for include in self._physical_includes(node):
                self._index_step()
                refid = include.attrs.get("refid", "")
                if not refid or _SUB.search(refid):
                    unknown = True
                    continue
                matches = self.fragments.get(self._key(namespace, refid), [])
                if len(matches) != 1:
                    unknown = True
                    continue
                fragment = matches[0][2]
                reachable.add(fragment)
                descendants, incomplete = self._reachable(namespace, fragment, stack + (key,))
                reachable.update(descendants)
                unknown |= incomplete
            if self.reachability_items + len(reachable) > MAX_REACHABILITY_ITEMS:
                raise _Rejected("include_index_resource_limit")
            self.reachability_items += len(reachable)
        except _Rejected:
            if "include_index_resource_limit" not in self.global_errors:
                self.global_errors.append("include_index_resource_limit")
            reachable, unknown = set(), True
        result = (frozenset(reachable), unknown)
        self._reachability_cache[key] = result
        return result

    def _callers(self, target):
        if target.tag in _STATEMENTS:
            return [entry for entry in self.statements if entry[2] is target]
        selected = []
        for entry in self.statements:
            reachable, unknown = self._reachable(entry[1], entry[2])
            if target in reachable or unknown:
                selected.append(entry)
        return selected

    def analyze(self, path, line, context, *, rule_id):
        if path in self.errors:
            context["unresolved"].append(self.errors[path])
            return
        if path not in self.documents:
            context["unresolved"].append("xml_not_available")
            return
        root, comments = self.documents[path]
        if any(start <= line <= end for start, end, _, _ in comments):
            # Mask actual parser spans, including multiline comment interiors;
            # executable XML before/after a comment boundary remains visible.
            source_line = list(self.texts[path].splitlines()[line - 1])
            for start, end, start_column, end_column in comments:
                if start <= line <= end:
                    left = start_column if line == start else 0
                    right = end_column if line == end else len(source_line)
                    source_line[left:right] = " " * (right - left)
            if not "".join(source_line).strip():
                context.update(classification="xml-comment", proposal="not_actionable")
                context["evidence_against"].append(_evidence("comment_not_executable_sql", path, line))
                return
        children = {part.tag for part in root.parts if isinstance(part, _Node)}
        log4j_tags = {"Properties", "Appenders", "Loggers", "CustomLevels", "Filters", "Scripts"}
        log4j = root.tag == "Configuration" and {"Appenders", "Loggers"} <= children and children <= log4j_tags
        if root.tag == "configuration" or log4j:
            if rule_id != "sqisoft-mybatis-xml-dollar-interpolation":
                context["unresolved"].append("configuration_candidate_claim_not_supported")
            elif not _configuration_substitution(root, self.texts[path], line):
                context["unresolved"].append("configuration_substitution_location_unsupported_or_ambiguous")
            else:
                context.update(classification="log4j-configuration" if log4j else "mybatis-configuration", proposal="not_actionable")
                kind = "logging_configuration_not_mybatis_statement" if log4j else "configuration_not_sql_statement"
                context["evidence_against"].append(_evidence(kind, path, line))
                context["limitations"].append("This counters only the exact MyBatis mapper interpolation claim at the supported configuration substitution location; configuration and lookup safety are not validated.")
            return
        if root.tag != "mapper":
            context["unresolved"].append("xml_not_a_supported_mapper")
            return
        candidates = [node for node in root.parts if isinstance(node, _Node) and node.line <= line <= node.end and node.tag in _STATEMENTS | {"sql"}]
        if len(candidates) != 1:
            context["unresolved"].append("candidate_sql_scope_ambiguous_or_missing")
            return
        target = candidates[0]
        self.target_nodes = set()
        pending = [target]
        while pending:
            current = pending.pop()
            self.target_nodes.add(current)
            pending.extend(part for part in current.parts if isinstance(part, _Node))
        issues = []
        for caller_path, namespace, statement in self._callers(target):
            hits, call_issues = [], []
            try:
                self._walk(caller_path, namespace, statement, {}, [], target, line, hits, call_issues, [], False)
            except _Rejected as exc:
                call_issues.append(str(exc))
            issues.extend(call_issues)
            for hit in hits:
                proposal = "not_actionable" if hit["binding"] in {"static", "parameter"} and not call_issues else "needs_review"
                instance = {
                    "caller": {"path": caller_path, "line": statement.line},
                    "location": {"path": path, "line": line},
                    "include_chain": hit["chain"], "binding": hit["binding"],
                    "branches": hit["branches"],
                    "proposal": proposal, "unresolved": sorted(set(call_issues)),
                }
                context["instances"].append(instance)
                side = "evidence_against" if hit["binding"] in {"static", "parameter"} else "evidence_for"
                context[side].append(_evidence("mybatis_" + hit["binding"] + "_binding", path, line,
                                               caller=instance["caller"], include_chain=hit["chain"]))
        if target.tag == "sql":
            issues.extend("mapper_index_incomplete:" + code for file, code in self.errors.items() if file.lower().endswith(".xml"))
            issues.extend(self.global_errors)
        if not context["instances"]:
            issues.append("candidate_has_no_resolved_call_instance")
        bindings = {item["binding"] for item in context["instances"]}
        if "runtime" in bindings:
            issues.append("runtime_substitution_attacker_control_and_guards_unproven")
        if "unknown" in bindings:
            issues.append("candidate_binding_not_resolved")
        context["unresolved"].extend(sorted(set(issues)))
        if context["instances"] and not issues and all(item["proposal"] == "not_actionable" for item in context["instances"]):
            context.update(classification="mybatis-static-or-parameter", proposal="not_actionable")
        elif len(bindings) > 1:
            context["classification"] = "mybatis-mixed-call-instances"
        elif "runtime" in bindings:
            context["classification"] = "mybatis-runtime"
        else:
            context["classification"] = "mybatis-unresolved"
        context["limitations"].append("Include properties are static XML-load substitutions. Conditional/loop branches are enumerated without executing OGNL or proving branch reachability; global configuration properties and Java mapper callers are not evaluated.")

    def _walk(self, path, namespace, node, env, stack, target, line, hits, issues, chain, included, branches=()):
        self.steps += 1
        if self.steps > MAX_CALLS or len(stack) > MAX_INCLUDE_DEPTH:
            raise _Rejected("include_resource_limit")
        if node.tag == "include":
            refid = self._substitute(node.attrs.get("refid", ""), env)
            if not refid or _SUB.search(refid):
                issues.append("include_refid_unresolved")
                return
            key = self._key(namespace, refid)
            if key in stack:
                issues.append("include_cycle")
                return
            matches = self.fragments.get(key, [])
            if len(matches) != 1:
                issues.append("include_fragment_missing_or_ambiguous")
                return
            local = dict(env)
            names = set()
            for prop in node.parts:
                if isinstance(prop, tuple) and not prop[0].strip():
                    continue
                if not isinstance(prop, _Node) or prop.tag != "property":
                    issues.append("include_child_unsupported")
                    return
                name = prop.attrs.get("name", "")
                if not name or name in names or "value" not in prop.attrs:
                    issues.append("include_property_duplicate_or_invalid")
                    return
                names.add(name)
                local[name] = self._substitute(prop.attrs["value"], env)
            child_path, _child_namespace, fragment = matches[0]
            # MyBatis retains the originating builder assistant throughout
            # expansion. Physical fragment location does not change its namespace.
            self._walk(child_path, namespace, fragment, local, stack + [key], target, line,
                       hits, issues, chain + [{"path": path, "line": node.line}], True, branches)
            return
        if node.tag not in _SQL_NODES:
            issues.append("dynamic_sql_node_unsupported")
        # Attributes are OGNL/configuration, never assumed to be SQL parameter
        # protection. Only actual SQL text nodes contribute binding evidence.
        for part in node.parts:
            if isinstance(part, _Node):
                branch = ({"tag": part.tag, "location": {"path": path, "line": part.line}},) if part.tag in _BRANCHES else ()
                self._walk(path, namespace, part, env, stack, target, line, hits, issues, chain, included, branches + branch)
            elif node in self.target_nodes:
                text, start = part
                for token in re.finditer(r"\$\{[^{}]+\}|#\{[^{}]+\}", text):
                    self.steps += 1
                    if self.steps > MAX_CALLS:
                        raise _Rejected("include_or_token_resource_limit")
                    token_line = start + text[:token.start()].count("\n")
                    if token_line != line:
                        continue
                    raw = token[0]
                    if raw.startswith("#{"):
                        binding = "parameter"
                    elif included:
                        binding = "runtime" if _SUB.search(self._substitute(raw, env)) else "static"
                    else:
                        binding = "runtime"
                    hits.append({"binding": binding, "chain": list(chain), "branches": list(branches)})

def _mask_comments(text):
    """Mask comments, preserving strings/newlines; unsupported JS stays unknown."""
    out = list(text)
    index, quote = 0, None
    while index < len(text):
        char = text[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in "\"'`":
            quote = char
        elif text.startswith("//", index) or text.startswith("/*", index) or text.startswith("<!--", index):
            if text.startswith("//", index):
                end = text.find("\n", index)
                end = len(text) if end < 0 else end
            else:
                closing = "-->" if text.startswith("<!--", index) else "*/"
                end = text.find(closing, index + 2)
                end = len(text) if end < 0 else end + len(closing)
            for cursor in range(index, end):
                if out[cursor] != "\n":
                    out[cursor] = " "
            index = end
            continue
        index += 1
    return "".join(out)


def _mask_strings(text):
    """Preserve code positions while hiding string/template contents."""
    out, index = list(text), 0
    while index < len(text):
        if text[index] not in "\"'`":
            index += 1
            continue
        quote, start = text[index], index
        index += 1
        while index < len(text):
            if text[index] == "\\":
                index += 2
            elif text[index] == quote:
                index += 1
                break
            else:
                index += 1
        for cursor in range(start, min(index, len(text))):
            if out[cursor] != "\n":
                out[cursor] = " "
    return "".join(out)


def _html_regions(text):
    """Identify actual HTML comments and script bodies without executing markup."""
    offsets = [0]
    offsets.extend(match.end() for match in re.finditer("\n", text))

    class Regions(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=False)
            self.comments, self.scripts, self.templates = [], [], []
            self.script, self.template_stack, self.invalid = None, [], False

        def source_offset(self):
            line, column = self.getpos()
            return offsets[line - 1] + column

        def handle_starttag(self, tag, attrs):
            start = self.source_offset()
            end = start + len(self.get_starttag_text())
            if tag == "script":
                if self.script is not None or len(dict(attrs)) != len(attrs):
                    self.invalid = True
                self.script = (end, dict(attrs))
            elif tag == "template":
                self.template_stack.append(end)

        def handle_startendtag(self, tag, attrs):
            if tag in {"script", "template"}:
                self.invalid = True

        def handle_endtag(self, tag):
            if tag == "script":
                if self.script is None:
                    self.invalid = True
                else:
                    start, attrs = self.script
                    self.scripts.append((start, self.source_offset(), attrs))
                    self.script = None
            elif tag == "template":
                if not self.template_stack:
                    self.invalid = True
                else:
                    self.templates.append((self.template_stack.pop(), self.source_offset()))

        def handle_comment(self, data):
            start = self.source_offset()
            end = text.find("-->", start)
            if end < 0:
                self.invalid = True
            else:
                self.comments.append((start, end + 3))

    parser = Regions()
    try:
        parser.feed(text)
        parser.close()
    except (ValueError, AssertionError):
        parser.invalid = True
    parser.invalid |= parser.script is not None or bool(parser.template_stack)
    clean = list(text)
    script_text = [char if char == "\n" else " " for char in text]
    for start, end in parser.comments:
        clean[start:end] = [char if char == "\n" else " " for char in text[start:end]]
    for start, end, attrs in parser.scripts:
        body = _mask_comments(text[start:end])
        clean[start:end] = body
        script_text[start:end] = body
    return "".join(clean), "".join(script_text), parser


def _html_context(text, path, line, context):
    markup = Path(path).suffix.lower() in {".vue", ".html"}
    regions = None
    if markup:
        clean, script_text, regions = _html_regions(text)
        if regions.invalid:
            context["unresolved"].append("mixed_html_script_boundaries_unresolved")
            return
    else:
        clean = script_text = _mask_comments(text)
    code = _mask_strings(clean)
    script_code = _mask_strings(script_text)
    lines, original = clean.splitlines(), text.splitlines()
    if not 0 < line <= len(lines):
        context["unresolved"].append("candidate_line_invalid")
        return
    current = lines[line - 1].strip()
    if not current and original[line - 1].strip():
        context.update(classification="javascript-comment", proposal="not_actionable")
        context["evidence_against"].append(_evidence("comment_not_executable_html", path, line))
        return
    context["classification"] = "html-render-path"
    # Restrict to the imported library and an exact one-argument sanitize call;
    # options, shadowing and post-sanitize concatenation stay unresolved.
    imports = [match for match in re.finditer(r"\bimport\s+([A-Za-z_$][\w$]*)\s+from\s+['\"]dompurify['\"]\s*;?", script_text)
               if script_code[match.start():match.start() + 6] == "import"]
    safe = False
    if len(imports) == 1:
        imported = imports[0]
        alias = imported[1]
        escaped = re.escape(alias)
        references = [match for match in re.finditer(r"\b" + escaped + r"\b", script_code)
                      if not imported.start() <= match.start() < imported.end()]
        shadowed = any(not re.match(r"\.sanitize\s*\(", script_code[match.end():]) for match in references)
        call = escaped + r"\.sanitize\(\s*[\w$.]+\s*\)"
        if not shadowed:
            code_line = code.splitlines()[line - 1]
            script_line = script_code.splitlines()[line - 1]
            safe = "innerHTML" in script_line and bool(re.fullmatch(r"[\w$.]+\.innerHTML\s*=\s*" + call + r"\s*;?", current))
            sinks = list(re.finditer(r"\bv-html\s*=\s*['\"]([A-Za-z_$][\w$]*)['\"]", current))
            setup = (regions is not None and Path(path).suffix.lower() == ".vue" and len(regions.scripts) == 1
                     and "setup" in regions.scripts[0][2] and "src" not in regions.scripts[0][2])
            line_start = sum(len(value) for value in clean.splitlines(keepends=True)[:line - 1])
            in_template = regions is not None and any(start <= line_start + clean.splitlines()[line - 1].find("v-html") < end for start, end in regions.templates)
            if setup and in_template and len(sinks) == 1 and "v-html" in code_line and not re.search(r"\bv-(?:for|slot)\b|#[\w-]+=", clean):
                sink = sinks[0]
                variable = re.escape(sink[1])
                declaration = re.compile(r"\bconst\s+" + variable + r"\s*=\s*(?:" + call + r"|computed\(\s*\(\)\s*=>\s*" + call + r"\s*\))\s*;")
                matches = [match for match in declaration.finditer(script_text) if script_code[match.start():match.start() + 5] == "const"]
                writes = re.findall(r"\b" + variable + r"(?:\.value)?\s*=(?!=)", script_code)
                top_level = len(matches) == 1 and script_code[:matches[0].start()].count("{") == script_code[:matches[0].start()].count("}")
                safe = top_level and len(writes) == 1
                if safe and "computed(" in matches[0][0]:
                    vue_imports = [match for match in re.finditer(r"\bimport\s*\{\s*computed\s*\}\s*from\s*['\"]vue['\"]", script_text)
                                   if script_code[match.start():match.start() + 6] == "import"]
                    safe = len(vue_imports) == 1 and not re.search(r"\b(?:const|let|var|function|class)\s+computed\b|\bcomputed\s*=(?!=)", script_code)
    if safe:
        context["classification"] = "dompurify-bound-render"
        context["evidence_against"].append(_evidence("dompurify_result_directly_rendered", path, line))
        # Proposal concerns the exact visible sink, never other render paths.
        context["proposal"] = "not_actionable"
        context["limitations"].append("DOMPurify evidence supports this exact simple render expression only; dynamic imports, library runtime configuration and other consumers are unverified.")
    else:
        context["unresolved"].append("html_input_sanitizer_identity_and_exact_render_flow_unresolved")


def _bound_query_context(text, path, line, context):
    clean = _mask_comments(text)
    lines = clean.splitlines()
    context["classification"] = "sql-query-binding"
    if not 0 < line <= len(lines):
        context["unresolved"].append("candidate_line_invalid")
        return
    # A fixed literal query and all named placeholders bound on the same local
    # receiver. Dynamic string construction or wrapper APIs remain unsupported.
    current = lines[line - 1].strip()
    query = re.fullmatch(r'(?:[\w<>.]+\s+)?([A-Za-z_]\w*)\s*=\s*[\w.]+\.(?:createQuery|createNativeQuery)\(\s*"([^"\\]*)"\s*\)\s*;', current)
    if query:
        receiver, literal = query.groups()
        names = set(re.findall(r"(?<!:):([A-Za-z_]\w*)", literal))
        tail = "\n".join(lines[line:line + 12])
        # Bound evidence stops at a basic-block boundary or receiver reassignment.
        tail = re.split(r"[{}]|\b" + re.escape(receiver) + r"\s*=(?!=)", tail, maxsplit=1)[0]
        bound = set(re.findall(r"(?:\A|(?<=;))\s*" + re.escape(receiver) + r'\.setParameter\(\s*"([A-Za-z_]\w*)"\s*,\s*[\w.]+\s*\)\s*;', tail))
        if names and names <= bound and not re.search(r"\b(?:if|for|while|switch|return|throw)\b", tail):
            context["proposal"] = "not_actionable"
            context["evidence_against"].append(_evidence("fixed_query_named_parameters_bound", path, line))
            context["limitations"].append("Only a fixed query literal and directly following local named parameter calls are modeled; application dataflow is not evaluated.")
            return
    prepared = re.fullmatch(r'(?:[\w<>.]+\s+)?([A-Za-z_]\w*)\s*=\s*[\w.]+\.prepareStatement\(\s*"([^"\\]*)"\s*\)\s*;', current)
    if prepared:
        receiver, literal = prepared.groups()
        # Quotes and SQL comments can contain question marks; those queries are
        # intentionally unsupported rather than counting non-parameter tokens.
        count = literal.count("?") if not re.search(r"['`]|--|/\*", literal) else 0
        tail = "\n".join(lines[line:line + 12])
        tail = re.split(r"[{}]|\b" + re.escape(receiver) + r"\s*=(?!=)", tail, maxsplit=1)[0]
        positions = {int(value) for value in re.findall(r"(?:\A|(?<=;))\s*" + re.escape(receiver) + r"\.set(?:String|Int|Long|Boolean|Double|Float|BigDecimal|Date|Timestamp|Object)\(\s*([1-9][0-9]{0,5})\s*,\s*[\w.]+\s*\)\s*;", tail)}
        if count and positions == set(range(1, count + 1)) and not re.search(r"\b(?:if|for|while|switch|return|throw)\b", tail):
            context["proposal"] = "not_actionable"
            context["evidence_against"].append(_evidence("fixed_prepared_statement_parameters_bound", path, line))
            context["limitations"].append("Only a fixed JDBC SQL literal and direct local positional setter calls are modeled.")
            return
    context["unresolved"].append("fixed_query_and_same_receiver_parameter_binding_not_established")


def contextualize_findings(source, inventory, findings):
    """Deep-copy every candidate and attach evidence-only context proposals."""
    texts, digests, errors, global_errors = _selected_source(source, inventory)
    mappers = _Mappers(texts, errors, global_errors)
    mappers.texts = texts
    results = []
    for original in findings:
        finding = deepcopy(original)
        context = _context()
        locations = finding.get("locations") or []
        location = locations[0] if locations and isinstance(locations[0], dict) else {}
        path = str(location.get("path", "")).replace("\\", "/")
        try:
            line = int(location.get("line", 0))
        except (TypeError, ValueError):
            line = 0
        family = _family(finding)
        if family == "unsupported":
            context["unresolved"].append("candidate_family_not_supported")
        elif len(locations) != 1:
            context["unresolved"].append("multiple_or_missing_candidate_locations")
        elif path not in texts:
            context["unresolved"].append(errors.get(path, "candidate_file_not_selected_or_available"))
        elif line < 1 or line > len(texts[path].splitlines()):
            context["unresolved"].append("candidate_line_invalid")
        elif family == "sql" and path.lower().endswith(".xml"):
            # Reset the per-finding expansion budget; one expensive candidate
            # cannot consume another candidate's context allowance.
            mappers.steps = 0
            mappers.analyze(path, line, context, rule_id=finding.get("rule_id"))
        elif family == "sql" and Path(path).suffix.lower() in {".java", ".kt"}:
            _bound_query_context(texts[path], path, line, context)
        elif family == "html" and Path(path).suffix.lower() in {".js", ".jsx", ".ts", ".tsx", ".vue", ".html"}:
            _html_context(texts[path], path, line, context)
        else:
            context["unresolved"].append("candidate_language_or_flow_not_supported")
        context["binding_digest"] = content_hash({
            "analyzer": ANALYZER, "files": digests, "errors": errors,
            "global_errors": global_errors, "location": location,
            "family": family, "context": context,
        })
        finding["context"] = context
        results.append(finding)
    return results
