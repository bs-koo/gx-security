"""Synthetic, non-executing contextual adjudication contracts."""
import copy
import hashlib
import importlib
import json

import pytest

from gxsec.models import make_finding


def analyze(tmp_path, files, *, path="Mapper.xml", line=2, rule="sql-injection", inventory_extra=(), inventory_errors=()):
    inventory = []
    for name, text in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        raw = target.read_bytes()
        inventory.append({"path": name, "hash": hashlib.sha256(raw).hexdigest(), "size": len(raw), "supported": True})
    finding = make_finding(category="sast", rule=rule, path=path, line=line, severity="High", validation="candidate")
    original = copy.deepcopy(finding)
    module = importlib.import_module("gxsec.contextual")
    result = module.contextualize_findings(tmp_path, {"inventory": inventory + list(inventory_extra), "errors": list(inventory_errors)}, [finding])
    assert finding == original
    assert len(result) == 1
    assert {k: v for k, v in result[0].items() if k != "context"} == original
    assert result[0] is not finding
    result[0]["locations"][0]["symbol"] = "copy only"
    assert finding == original
    context = result[0]["context"]
    assert set(("schema_version", "analyzer", "classification", "proposal", "evidence_for", "evidence_against", "unresolved", "instances", "limitations", "binding_digest")) <= context.keys()
    assert len(context["binding_digest"]) == 64
    return context


def test_runtime_substitution_is_not_suppressed(tmp_path):
    context = analyze(tmp_path, {"Mapper.xml": '<mapper namespace="m">\n<select id="s">select * from t order by ${sort}</select>\n</mapper>'})
    assert context["proposal"] == "needs_review"
    assert context["evidence_for"]


def test_static_include_is_per_call_and_does_not_leak_values(tmp_path):
    text = '<mapper namespace="m">\n<sql id="f">order by ${column}</sql>\n<select id="s">select * from t <include refid="f"><property name="column" value="PRIVATE_COLUMN_LITERAL"/></include></select>\n</mapper>'
    context = analyze(tmp_path, {"Mapper.xml": text})
    assert context["proposal"] == "not_actionable"
    assert len(context["instances"]) == 1
    assert context["evidence_against"]
    assert "PRIVATE_COLUMN_LITERAL" not in json.dumps(context)


def test_mixed_fragment_callers_are_retained(tmp_path):
    text = '<mapper namespace="m">\n<sql id="f">order by ${column}</sql>\n<select id="safe"><include refid="f"><property name="column" value="id"/></include></select>\n<select id="unsafe"><include refid="f"/></select>\n</mapper>'
    context = analyze(tmp_path, {"Mapper.xml": text})
    assert context["proposal"] == "needs_review"
    assert len(context["instances"]) == 2
    assert {x["proposal"] for x in context["instances"]} == {"needs_review", "not_actionable"}
    assert context["evidence_for"] and context["evidence_against"]


def test_cross_namespace_nested_properties_follow_parent_scope(tmp_path):
    files = {
        "Mapper.xml": '<mapper namespace="shared">\n<sql id="leaf">order by ${column}</sql>\n<sql id="wrapper"><include refid="leaf"><property name="column" value="${outer}"/></include></sql>\n</mapper>',
        "Call.xml": '<mapper namespace="calls"><select id="s"><include refid="shared.wrapper"><property name="outer" value="FIXED_PRIVATE"/></include></select></mapper>',
    }
    context = analyze(tmp_path, files)
    # Unqualified leaf resolves against the originating calls builder, not shared.
    assert context["proposal"] == "needs_review"
    assert not context["instances"]
    assert context["unresolved"]
    assert "FIXED_PRIVATE" not in json.dumps(context)


def test_explicit_cross_namespace_nested_property_is_resolved(tmp_path):
    files = {
        "Mapper.xml": '<mapper namespace="shared">\n<sql id="leaf">order by ${column}</sql>\n<sql id="wrapper"><include refid="shared.leaf"><property name="column" value="${outer}"/></include></sql>\n</mapper>',
        "Call.xml": '<mapper namespace="calls"><select id="s"><include refid="shared.wrapper"><property name="outer" value="FIXED_PRIVATE"/></include></select></mapper>',
    }
    context = analyze(tmp_path, files)
    assert context["proposal"] == "not_actionable"
    assert len(context["instances"]) == 1
    assert "FIXED_PRIVATE" not in json.dumps(context)


@pytest.mark.parametrize("body", [
    '<sql id="f">${column}</sql>',
    '<sql id="f">${column}<include refid="missing"/></sql><select id="s"><include refid="f"/></select>',
    '<sql id="f">${column}<include refid="f"/></sql><select id="s"><include refid="f"/></select>',
    '<sql id="f">${column}</sql><select id="s"><include refid="${dynamic}"/></select>',
    '<sql id="f">${column}</sql><select id="s"><include refid="f"><property name="column" value="id"/><property name="column" value="name"/></include></select>',
])
def test_unreachable_unknown_cycle_and_invalid_scopes_require_review(tmp_path, body):
    context = analyze(tmp_path, {"Mapper.xml": '<mapper namespace="m">\n' + body + '\n</mapper>'})
    assert context["proposal"] == "needs_review"
    assert context["unresolved"]


@pytest.mark.parametrize("text,expected", [
    ('<mapper namespace="m">\n<!-- ${comment} -->\n<select id="s">select 1</select></mapper>', "not_actionable"),
    ('<configuration>\n<property name="url" value="${config}"/>\n</configuration>', "needs_review"),
    ('<mapper namespace="m">\n<select id="s">where id = #{id}</select>\n</mapper>', "not_actionable"),
    ('<mapper namespace="m">\n<select id="s">${sort}</mapper>', "needs_review"),
    ('<!DOCTYPE mapper SYSTEM "https://example.invalid/mybatis.dtd">\n<mapper namespace="m"><select id="s">${sort}</select></mapper>', "needs_review"),
    ('<!DOCTYPE mapper [<!ENTITY x SYSTEM "file:///private">]>\n<mapper namespace="m"><select id="s">&x;</select></mapper>', "needs_review"),
    ('<mapper namespace="m">\n' + '<if test="x">' * 150 + '${sort}' + '</if>' * 150 + '</mapper>', "needs_review"),
])
def test_xml_real_scopes_comments_binding_and_parser_boundaries(tmp_path, text, expected):
    assert analyze(tmp_path, {"Mapper.xml": text})["proposal"] == expected


def test_unselected_and_hash_changed_files_never_supply_safety(tmp_path):
    (tmp_path / "Mapper.xml").write_text('<mapper namespace="m">\n<select id="s">#{id}</select></mapper>')
    context = analyze(tmp_path, {}, inventory_extra=[{"path": "Mapper.xml", "hash": "0" * 64}])
    assert context["proposal"] == "needs_review"
    assert context["unresolved"]


def test_path_escape_is_not_read(tmp_path):
    context = analyze(tmp_path, {}, path="../private.xml", inventory_extra=[{"path": "../private.xml"}])
    assert context["proposal"] == "needs_review"


@pytest.mark.parametrize("body,expected", [
    ('// element.innerHTML = unsafe;', "not_actionable"),
    ('element.innerHTML = DOMPurify.sanitize(raw);', "not_actionable"),
    ('element.innerHTML = DOMPurify.sanitize(raw) + unsafe;', "needs_review"),
    ('const safe = DOMPurify.sanitize(raw);\nelement.innerHTML = unsafe;', "needs_review"),
    ('element.innerHTML = sanitizeHtml(raw);', "needs_review"),
])
def test_js_sanitizer_is_bound_to_the_actual_sink(tmp_path, body, expected):
    text = 'import DOMPurify from "dompurify";\n' + body
    assert analyze(tmp_path, {"View.js": text}, path="View.js", rule="xss")["proposal"] == expected


def test_vue_computed_sanitizer_connection(tmp_path):
    text = '<script setup>\nimport DOMPurify from "dompurify";\nimport { computed } from "vue";\nconst safe = computed(() => DOMPurify.sanitize(raw));\n</script>\n<template><div v-html="safe" /></template>'
    assert analyze(tmp_path, {"View.vue": text}, path="View.vue", line=6, rule="xss")["proposal"] == "not_actionable"


@pytest.mark.parametrize("text,expected", [
    ('Query q = em.createQuery("select u from User u where u.name = :name");\nq.setParameter("name", input);', "not_actionable"),
    ('Query q = em.createQuery("select u from User u where u.name = " + input);\nq.setParameter("name", input);', "needs_review"),
    ('Query q = em.createQuery(query);\nother.setParameter("name", input);', "needs_review"),
])
def test_jpql_binding_must_match_fixed_query(tmp_path, text, expected):
    assert analyze(tmp_path, {"Repo.java": text}, path="Repo.java", line=1)["proposal"] == expected


def test_unknown_family_is_explicit_and_digest_changes_with_callers(tmp_path):
    files = {"Mapper.xml": '<mapper namespace="m">\n<sql id="f">${c}</sql>\n<select id="s"><include refid="f"><property name="c" value="id"/></include></select></mapper>'}
    first = analyze(tmp_path, files)
    files["Mapper.xml"] = files["Mapper.xml"].replace('value="id"', 'value="name"')
    second = analyze(tmp_path, files)
    assert first["binding_digest"] != second["binding_digest"]
    unknown = analyze(tmp_path, files, rule="credential-exposure")
    assert unknown["proposal"] == "needs_review"
    assert unknown["unresolved"]


@pytest.mark.parametrize("body", [
    'const safe = computed(() => DOMPurify.sanitize(raw));\n<template><div v-html="safe" /></template>',
    'const unrelated = DOMPurify;\nfunction render(DOMPurify) {\nelement.innerHTML = DOMPurify.sanitize(raw);\n}',
    'const unrelated = DOMPurify;\nconst render = (DOMPurify) => {\nelement.innerHTML = DOMPurify.sanitize(raw);\n};',
    'const s = `\nelement.innerHTML = DOMPurify.sanitize(raw);\n`;',
    'function render(raw) {\nconst safe = DOMPurify.sanitize(raw);\n}\n<template><div v-html="safe" /></template>',
    'const safe = computed(() => DOMPurify.sanitize(raw));\n<template><div v-for="safe in values" v-html="safe" /></template>',
    'DOMPurify["sanitize"] = custom;\nelement.innerHTML = DOMPurify.sanitize(raw);',
])
def test_sanitizer_alias_shadowing_and_lexical_ambiguity_are_not_safety(tmp_path, body):
    text = 'import DOMPurify from "dompurify";\n' + body
    sink_line = next(index for index, value in enumerate(text.splitlines(), 1) if "innerHTML" in value or "v-html" in value)
    context = analyze(tmp_path, {"View.vue": text}, path="View.vue", line=sink_line, rule="xss")
    assert context["proposal"] == "needs_review"


@pytest.mark.parametrize("binding", [
    'other.setParameter("name", input);',
    'if (allowed) q.setParameter("name", input);',
    'q = other; q.setParameter("name", input);',
    'q.setParameter("name", input); return q; q = other;',
    'String unrelated = "q.setParameter(\\"name\\", input);";',
])
def test_jpql_conditional_or_wrong_receiver_does_not_prove_binding(tmp_path, binding):
    text = 'Query q = em.createQuery("select u from User u where u.name = :name");\n' + binding
    assert analyze(tmp_path, {"Repo.java": text}, path="Repo.java", line=1)["proposal"] == "needs_review"


def test_selected_file_limit_keeps_incomplete_fragment_callers_unknown(tmp_path, monkeypatch):
    module = importlib.import_module("gxsec.contextual")
    monkeypatch.setattr(module, "MAX_FILES", 1)
    files = {
        "Mapper.xml": '<mapper namespace="m">\n<sql id="f">${column}</sql>\n<select id="safe"><include refid="f"><property name="column" value="id"/></include></select></mapper>',
        "Unknown.xml": '<mapper namespace="other"><select id="unsafe"><include refid="m.f"/></select></mapper>',
    }
    context = analyze(tmp_path, files)
    assert context["proposal"] == "needs_review"
    assert context["unresolved"]


def test_binding_expansion_and_token_counts_are_bounded(tmp_path, monkeypatch):
    module = importlib.import_module("gxsec.contextual")
    monkeypatch.setattr(module, "MAX_CALLS", 20)
    text = '<mapper namespace="m">\n<select id="s">' + '${p}' * 100 + '</select>\n</mapper>'
    context = analyze(tmp_path, {"Mapper.xml": text})
    assert context["proposal"] == "needs_review"
    assert len(context["instances"]) <= 20
    assert any("limit" in issue for issue in context["unresolved"])


def test_static_bindings_with_incomplete_selected_xml_do_not_refute_fragment(tmp_path):
    files = {
        "Mapper.xml": '<mapper namespace="m">\n<sql id="f">${column}</sql>\n<select id="safe"><include refid="f"><property name="column" value="id"/></include></select></mapper>',
        "Unknown.xml": '<mapper namespace="other"><select',
    }
    context = analyze(tmp_path, files)
    assert context["proposal"] == "needs_review"
    assert context["instances"] and context["unresolved"]


def test_non_comment_sql_on_comment_line_is_not_refuted(tmp_path):
    text = '<mapper namespace="m">\n<select id="s">${user}</select><!-- note -->\n</mapper>'
    assert analyze(tmp_path, {"Mapper.xml": text})["proposal"] == "needs_review"


def test_bound_parameter_and_runtime_substitution_on_one_line_remain_review(tmp_path):
    text = '<mapper namespace="m">\n<select id="s">where id = #{id} order by ${sort}</select>\n</mapper>'
    context = analyze(tmp_path, {"Mapper.xml": text})
    assert context["proposal"] == "needs_review"
    assert context["evidence_for"] and context["evidence_against"]


def test_include_property_scope_does_not_escape_to_sibling_call(tmp_path):
    text = '<mapper namespace="m">\n<sql id="f">${column}</sql>\n<select id="s"><include refid="f"><property name="column" value="id"/></include><include refid="f"/></select></mapper>'
    context = analyze(tmp_path, {"Mapper.xml": text})
    assert context["proposal"] == "needs_review"
    assert [instance["binding"] for instance in context["instances"]] == ["static", "runtime"]


def test_namespace_collision_never_borrows_another_mapper_property(tmp_path):
    files = {
        "Mapper.xml": '<mapper namespace="a">\n<sql id="f">${column}</sql>\n<select id="s"><include refid="f"/></select></mapper>',
        "Other.xml": '<mapper namespace="b"><sql id="f">${column}</sql><select id="s"><include refid="f"><property name="column" value="id"/></include></select></mapper>',
    }
    context = analyze(tmp_path, files)
    assert context["proposal"] == "needs_review"
    assert len(context["instances"]) == 1
    assert context["instances"][0]["binding"] == "runtime"


def test_duplicate_fragment_ids_remain_ambiguous(tmp_path):
    files = {
        "Mapper.xml": '<mapper namespace="m">\n<sql id="f">${column}</sql>\n<select id="s"><include refid="f"><property name="column" value="id"/></include></select></mapper>',
        "Duplicate.xml": '<mapper namespace="m"><sql id="f">${column}</sql></mapper>',
    }
    context = analyze(tmp_path, files)
    assert context["proposal"] == "needs_review"
    assert context["unresolved"]


def test_safe_property_and_runtime_property_values_are_distinguished(tmp_path):
    text = '<mapper namespace="m">\n<sql id="f">${column}</sql>\n<select id="s"><include refid="f"><property name="column" value="${request.value}"/></include></select></mapper>'
    context = analyze(tmp_path, {"Mapper.xml": text})
    assert context["proposal"] == "needs_review"
    assert context["instances"][0]["binding"] == "runtime"


def test_bound_expansion_stops_property_amplification(tmp_path, monkeypatch):
    module = importlib.import_module("gxsec.contextual")
    monkeypatch.setattr(module, "MAX_BINDING_BYTES", 16)
    text = '<mapper namespace="m">\n<sql id="f">${column}</sql>\n<select id="s"><include refid="f"><property name="column" value="' + 'x' * 20 + '"/></include></select></mapper>'
    context = analyze(tmp_path, {"Mapper.xml": text})
    assert context["proposal"] == "needs_review"
    assert any("limit" in issue for issue in context["unresolved"])


def test_selected_oversize_file_is_explicitly_unresolved(tmp_path, monkeypatch):
    module = importlib.import_module("gxsec.contextual")
    monkeypatch.setattr(module, "MAX_FILE_BYTES", 30)
    context = analyze(tmp_path, {"Mapper.xml": '<mapper namespace="m">\n<select id="s">#{id}</select></mapper>'})
    assert context["proposal"] == "needs_review"
    assert any("limit" in issue for issue in context["unresolved"])


def test_xml_entity_expansion_is_rejected_before_parsing_values(tmp_path):
    text = '<!DOCTYPE mapper [<!ENTITY a "secret-literal"><!ENTITY b "&a;&a;">]>\n<mapper namespace="m"><select id="s">&b;</select></mapper>'
    context = analyze(tmp_path, {"Mapper.xml": text})
    assert context["proposal"] == "needs_review"
    assert "secret-literal" not in json.dumps(context)


@pytest.mark.parametrize("body", [
    'const computed = ignored => unsafe;\nconst safe = computed(() => DOMPurify.sanitize(raw));\n<template><div v-html="safe" /></template>',
    'const safe = DOMPurify.sanitize(raw);\n<template><div v-html="safe" v-html="unsafe" /></template>',
    'const safe = DOMPurify.sanitize(raw);\nObject.assign(DOMPurify, custom);\n<template><div v-html="safe" /></template>',
    'const safe = DOMPurify.sanitize(raw, options);\n<template><div v-html="safe" /></template>',
    'const safe = DOMPurify.sanitize(raw);\nsafe.value = unsafe;\n<template><div v-html="safe" /></template>',
])
def test_vue_wrapper_mutation_options_and_multiple_sink_ambiguity_stay_review(tmp_path, body):
    text = 'import DOMPurify from "dompurify";\n' + body
    sink_line = next(index for index, value in enumerate(text.splitlines(), 1) if "v-html" in value)
    assert analyze(tmp_path, {"View.vue": text}, path="View.vue", line=sink_line, rule="xss")["proposal"] == "needs_review"


def test_jdbc_fixed_prepared_statement_parameters_are_matched_to_receiver(tmp_path):
    text = 'PreparedStatement ps = connection.prepareStatement("select * from t where name = ?");\nps.setString(1, input);'
    context = analyze(tmp_path, {"Repo.java": text}, path="Repo.java", line=1)
    assert context["proposal"] == "not_actionable"
    assert context["evidence_against"]


@pytest.mark.parametrize("binding", ['other.setString(1, input);', 'ps.setString(2, input);', 'if (check) ps.setString(1, input);'])
def test_jdbc_unbound_or_conditional_parameters_stay_review(tmp_path, binding):
    text = 'PreparedStatement ps = connection.prepareStatement("select * from t where name = ?");\n' + binding
    assert analyze(tmp_path, {"Repo.java": text}, path="Repo.java", line=1)["proposal"] == "needs_review"


def test_review_i1_xml_comment_sandwich_preserves_executable_sql(tmp_path):
    text = '<mapper namespace="m">\n<!-- a --> <select id="s">${user}</select> <!-- b -->\n</mapper>'
    context = analyze(tmp_path, {"Mapper.xml": text})
    assert context["proposal"] == "needs_review"
    assert context["instances"] and context["evidence_for"]


@pytest.mark.parametrize("path", ["View.vue", "View.html"])
@pytest.mark.parametrize("prefix", ["//", "/*"])
def test_review_i2_template_slashes_are_not_javascript_comments(tmp_path, path, prefix):
    text = '<template>\n' + prefix + ' <div v-html="raw" />\n</template>'
    context = analyze(tmp_path, {path: text}, path=path, rule="xss")
    assert context["proposal"] == "needs_review"
    assert context["unresolved"]


@pytest.mark.parametrize("path", ["View.vue", "View.html"])
def test_html_comment_only_location_remains_counterevidence(tmp_path, path):
    text = '<template>\n<!-- <div v-html="raw" /> -->\n</template>'
    context = analyze(tmp_path, {path: text}, path=path, rule="xss")
    assert context["proposal"] == "not_actionable"
    assert context["evidence_against"]


def test_script_region_javascript_comment_still_supported(tmp_path):
    text = '<script setup>\n// element.innerHTML = raw;\n</script>'
    assert analyze(tmp_path, {"View.vue": text}, path="View.vue", rule="xss")["proposal"] == "not_actionable"


def test_review_i3_normal_module_const_is_not_vue_template_binding(tmp_path):
    text = '<script>\nimport DOMPurify from "dompurify";\nconst safe = DOMPurify.sanitize(raw);\nexport default { data() { return { safe: location.hash }; } };\n</script>\n<template><div v-html="safe" /></template>'
    context = analyze(tmp_path, {"View.vue": text}, path="View.vue", line=6, rule="xss")
    assert context["proposal"] == "needs_review"
    assert context["unresolved"]


def test_script_setup_direct_const_is_proven_template_binding(tmp_path):
    text = '<script setup>\nimport DOMPurify from "dompurify";\nconst safe = DOMPurify.sanitize(raw);\n</script>\n<template><div v-html="safe" /></template>'
    assert analyze(tmp_path, {"View.vue": text}, path="View.vue", line=5, rule="xss")["proposal"] == "not_actionable"


def test_review_i4_nested_includes_retain_originating_builder_namespace(tmp_path):
    files = {
        "Mapper.xml": '<mapper namespace="a">\n<sql id="leaf">${column}</sql>\n<select id="safe"><include refid="leaf"><property name="column" value="id"/></include></select>\n<select id="unsafe"><include refid="b.wrapper"/></select>\n</mapper>',
        "Other.xml": '<mapper namespace="b">\n<sql id="wrapper"><include refid="leaf"/></sql>\n<sql id="leaf">${column}</sql>\n</mapper>',
    }
    context = analyze(tmp_path, files)
    assert context["proposal"] == "needs_review"
    assert len(context["instances"]) == 2
    assert {item["caller"]["line"] for item in context["instances"]} == {3, 4}
    assert {item["binding"] for item in context["instances"]} == {"static", "runtime"}
    assert context["evidence_for"] and context["evidence_against"]


@pytest.mark.parametrize("query,binding", [
    ('Query q = em.createQuery("select u from User u where u.name = :name");', 'other.q.setParameter("name", input);'),
    ('PreparedStatement ps = connection.prepareStatement("select * from t where name = ?");', 'other.ps.setString(1, input);'),
    ('Query q = em.createQuery("select u from User u where u.name = :name");', 'other . q.setParameter("name", input);'),
])
def test_review_i5_member_suffix_is_not_the_same_query_receiver(tmp_path, query, binding):
    context = analyze(tmp_path, {"Repo.java": query + '\n' + binding}, path="Repo.java", line=1)
    assert context["proposal"] == "needs_review"
    assert not context["evidence_against"]


@pytest.mark.parametrize("query,binding", [
    ('Query q = em.createQuery("select u from User u where u.name = :name");', 'other.\nq.setParameter("name", input);'),
    ('PreparedStatement ps = connection.prepareStatement("select * from t where name = ?");', 'other.\nps.setString(1, input);'),
])
def test_review_i5_multiline_member_continuation_is_not_local_receiver(tmp_path, query, binding):
    context = analyze(tmp_path, {"Repo.java": query + '\n' + binding}, path="Repo.java", line=1)
    assert context["proposal"] == "needs_review"
    assert not context["evidence_against"]


def test_review_i6_upstream_inventory_errors_invalidate_fragment_completeness(tmp_path):
    files = {"Mapper.xml": '<mapper namespace="m">\n<sql id="f">${column}</sql>\n<select id="safe"><include refid="f"><property name="column" value="id"/></include></select>\n</mapper>'}
    complete = analyze(tmp_path, files)
    incomplete = analyze(tmp_path, files, inventory_errors=[{"path": "Unreadable.xml", "error": "PRIVATE_ERROR_VALUE"}])
    assert complete["proposal"] == "not_actionable"
    assert incomplete["proposal"] == "needs_review"
    assert incomplete["unresolved"]
    assert incomplete["binding_digest"] != complete["binding_digest"]
    assert "PRIVATE_ERROR_VALUE" not in json.dumps(incomplete)


def test_upstream_directory_reparse_error_invalidates_missing_caller_index(tmp_path):
    files = {"Mapper.xml": '<mapper namespace="m">\n<sql id="f">${column}</sql>\n<select id="safe"><include refid="f"><property name="column" value="id"/></include></select>\n</mapper>'}
    context = analyze(tmp_path, files, inventory_errors=[{"type": "reparse_entry", "path": "unreadable-directory"}])
    assert context["proposal"] == "needs_review"
    assert context["unresolved"]


@pytest.mark.parametrize("runtime_caller", [False, True])
def test_normal_mapper_corpus_does_not_exhaust_unrelated_call_expansions(tmp_path, runtime_caller):
    files = {
        "Mapper.xml": '<mapper namespace="m">\n<sql id="target">${column}</sql>\n<select id="safe"><include refid="target"><property name="column" value="id"/></include></select>\n</mapper>',
    }
    if runtime_caller:
        files["Mapper.xml"] = files["Mapper.xml"].replace('\n</mapper>', '\n<select id="runtime"><include refid="target"/></select>\n</mapper>')
    for index in range(96):
        body = '<sql id="other"><if test="enabled"><foreach collection="items" item="item">#{item}</foreach></if></sql>'
        body += ''.join('<select id="s' + str(number) + '"><include refid="other"/></select>' for number in range(10))
        files['Other' + str(index) + '.xml'] = '<mapper namespace="other' + str(index) + '">' + body + '</mapper>'
    context = analyze(tmp_path, files)
    assert context["proposal"] == ("needs_review" if runtime_caller else "not_actionable")
    assert len(context["instances"]) == (2 if runtime_caller else 1)
    if runtime_caller:
        assert {item["binding"] for item in context["instances"]} == {"static", "runtime"}
        assert context["evidence_for"] and context["evidence_against"]
    else:
        assert not context["unresolved"]


@pytest.mark.parametrize("dynamic", [
    '<if test="enabled">${column}</if>',
    '<choose><when test="enabled">${column}</when><otherwise>${column}</otherwise></choose>',
    '<where><trim prefix="AND"><foreach collection="items" item="column">${column}</foreach></trim></where>',
    '<bind name="column" value="runtimeExpression"/>${column}',
])
def test_xml_load_static_properties_survive_conditional_and_loop_runtime_scopes(tmp_path, dynamic):
    files = {"Mapper.xml": '<mapper namespace="m">\n<sql id="target">' + dynamic + '</sql>\n<select id="safe"><include refid="target"><property name="column" value="id"/></include></select>\n</mapper>'}
    context = analyze(tmp_path, files)
    assert context["proposal"] == "not_actionable"
    assert context["instances"]
    assert {item["binding"] for item in context["instances"]} == {"static"}
    assert not context["unresolved"]


def test_runtime_loop_binding_stays_review_alongside_static_branch_caller(tmp_path):
    text = '<mapper namespace="m">\n<sql id="target"><if test="enabled"><foreach collection="items" item="column">${column}</foreach></if></sql>\n<select id="safe"><include refid="target"><property name="column" value="id"/></include></select>\n<select id="runtime"><include refid="target"/></select>\n</mapper>'
    context = analyze(tmp_path, {"Mapper.xml": text})
    assert context["proposal"] == "needs_review"
    assert {item["binding"] for item in context["instances"]} == {"static", "runtime"}
    assert context["evidence_for"] and context["evidence_against"]


def test_unknown_dynamic_refid_caller_prevents_static_fragment_completeness(tmp_path):
    files = {
        "Mapper.xml": '<mapper namespace="m">\n<sql id="target">${column}</sql>\n<select id="safe"><include refid="target"><property name="column" value="id"/></include></select></mapper>',
        "Unknown.xml": '<mapper namespace="u"><select id="unknown"><include refid="${dynamic}"/></select></mapper>',
    }
    context = analyze(tmp_path, files)
    assert context["proposal"] == "needs_review"
    assert context["unresolved"]


def test_multiline_xml_comment_location_is_narrow_counterevidence(tmp_path):
    text = '<mapper namespace="m">\n<!-- template example\n<select id="commented">${user}</select>\n-->\n<select id="real">#{id}</select>\n</mapper>'
    context = analyze(tmp_path, {"Mapper.xml": text}, line=3)
    assert context["proposal"] == "not_actionable"
    assert not context["instances"]
    assert context["evidence_against"]


@pytest.mark.parametrize("line", [2, 3])
def test_multiline_comment_boundary_with_executable_sql_is_not_erased(tmp_path, line):
    text = '<mapper namespace="m">\n<select id="first">${user}</select><!-- comment\nend --><select id="second">${user}</select>\n</mapper>'
    context = analyze(tmp_path, {"Mapper.xml": text}, line=line)
    assert context["proposal"] == "needs_review"
    assert context["evidence_for"]


def test_explicit_log4j_configuration_is_not_mybatis_sql(tmp_path):
    text = '<Configuration status="WARN">\n<Properties><Property name="logPath">${runtimePath}</Property></Properties>\n<Appenders/><Loggers/></Configuration>'
    context = analyze(tmp_path, {"Mapper.xml": text}, rule="sqisoft-mybatis-xml-dollar-interpolation")
    assert context["proposal"] == "not_actionable"
    assert context["evidence_against"]


@pytest.mark.parametrize("rule", ["sql-injection", "sqisoft-mybatis-xml-dollar-interpolation"])
@pytest.mark.parametrize("body,line", [
    ('<Scripts><Script name="query" language="groovy"><![CDATA[\nconnection.createStatement().executeQuery("SELECT * FROM records WHERE id = " + userInput)\n]]></Script></Scripts>', 3),
    ('<Appenders><JDBC name="db"><Column name="value" literal="${user}"/></JDBC></Appenders>', 2),
    ('<Properties><Custom>${value}</Custom></Properties>', 2),
    ('<Properties><Property name="p">${value}</Property><Custom>${other}</Custom></Properties>', 2),
    ('<Properties name="${other}"><Property name="p">${value}</Property></Properties>', 2),
    ('<Properties><Property name="p">${value}</Property><Property name="q">${other}</Property></Properties>', 2),
    ('<Appenders><Custom><PatternLayout pattern="${value}"/></Custom></Appenders>', 2),
    ('<Appenders><Console><PatternLayout custom="${value}"/></Console></Appenders>', 2),
    ('<Properties>\n<Property name="p">fixed</Property>\n</Properties>', 3),
])
def test_configuration_claim_unsupported_log4j_locations_need_review(tmp_path, rule, body, line):
    text = '<Configuration>\n' + body + '\n<Appenders/><Loggers/>\n</Configuration>'
    context = analyze(tmp_path, {"Mapper.xml": text}, rule=rule, line=line)
    assert context["proposal"] == "needs_review"
    assert context["unresolved"]
    assert not context["evidence_against"]


@pytest.mark.parametrize("rule,expected", [
    ("sqisoft-mybatis-xml-dollar-interpolation", "not_actionable"),
    ("sql-injection", "needs_review"),
    ("custom-sqisoft-mybatis-xml-dollar-interpolation", "needs_review"),
])
@pytest.mark.parametrize("body,line", [
    ('<Properties><Property name="path">${value}</Property></Properties>', 2),
    ('<Appenders><Console><PatternLayout pattern="${value}"/></Console></Appenders>', 2),
    ('<Appenders>\n<RollingFile name="r"\n fileName="${value}" filePattern="${archive}">\n</RollingFile></Appenders>', 4),
    ('<Appenders><RollingFile><PatternLayout pattern="${value}"/></RollingFile></Appenders>', 2),
    ('<Appenders><RollingFile><DefaultRolloverStrategy><Delete basePath="${value}"/></DefaultRolloverStrategy></RollingFile></Appenders>', 2),
])
def test_configuration_claim_supported_log4j_substitutions(tmp_path, rule, expected, body, line):
    text = '<Configuration>\n' + body + '\n<Loggers/>\n</Configuration>'
    if body.startswith('<Properties>'):
        text = text.replace('<Loggers/>', '<Appenders/><Loggers/>')
    context = analyze(tmp_path, {"Mapper.xml": text}, rule=rule, line=line)
    assert context["proposal"] == expected


@pytest.mark.parametrize("rule,expected", [
    ("sqisoft-mybatis-xml-dollar-interpolation", "not_actionable"),
    ("sql-injection", "needs_review"),
])
def test_configuration_claim_mybatis_property_requires_exact_rule(tmp_path, rule, expected):
    text = '<configuration>\n<properties><property name="url" value="${config}"/></properties>\n</configuration>'
    context = analyze(tmp_path, {"Mapper.xml": text}, rule=rule)
    assert context["proposal"] == expected


@pytest.mark.parametrize("body", [
    '<Scripts><Script>${user}</Script></Scripts>',
    '<custom><property name="sql" value="${user}"/></custom>',
    '<properties><property name="url" value="${config}"/><custom>${user}</custom></properties>',
])
def test_configuration_claim_lowercase_custom_context_needs_review(tmp_path, body):
    context = analyze(tmp_path, {"Mapper.xml": '<configuration>\n' + body + '\n</configuration>'}, rule="sqisoft-mybatis-xml-dollar-interpolation")
    assert context["proposal"] == "needs_review"
    assert context["unresolved"]


def test_unknown_uppercase_configuration_root_is_not_globally_safe(tmp_path):
    text = '<Configuration>\n<SQL>${runtime}</SQL>\n</Configuration>'
    context = analyze(tmp_path, {"Mapper.xml": text})
    assert context["proposal"] == "needs_review"
    assert context["unresolved"]


def test_reachability_index_exhaustion_is_explicitly_unresolved(tmp_path, monkeypatch):
    module = importlib.import_module("gxsec.contextual")
    monkeypatch.setattr(module, "MAX_INDEX_STEPS", 1, raising=False)
    text = '<mapper namespace="m">\n<sql id="target">${column}</sql>\n<select id="safe"><include refid="target"><property name="column" value="id"/></include></select></mapper>'
    context = analyze(tmp_path, {"Mapper.xml": text})
    assert context["proposal"] == "needs_review"
    assert any("index" in issue and "limit" in issue for issue in context["unresolved"])


def test_unknown_sql_language_node_does_not_inherit_branch_support(tmp_path):
    text = '<mapper namespace="m">\n<sql id="target"><customSqlLanguage>${column}</customSqlLanguage></sql>\n<select id="safe"><include refid="target"><property name="column" value="id"/></include></select></mapper>'
    context = analyze(tmp_path, {"Mapper.xml": text})
    assert context["proposal"] == "needs_review"
    assert context["unresolved"]
