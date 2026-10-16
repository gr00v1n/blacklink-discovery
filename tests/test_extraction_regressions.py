import pytest

from blacklink_discovery.extract import extract
from blacklink_discovery.text import Positions


@pytest.mark.parametrize(
    "kind,text,expected",
    [
        ("json", r'{"host":"api\u002eexample\u002enet"}', "api.example.net"),
        ("css", r"url(https://api\2e example\2e net/x)", "api.example.net"),
        ("text", "例子。测试", "xn--fsqu00a.xn--0zwm56d"),
        ("text", "cafe\u0301.example.net", "xn--caf-dma.example.net"),
        ("text", "访问example.com即可", "example.com"),
        ("js", 'const h="cdn.\\\r\nexample.net";', "cdn.example.net"),
        ("html", '<script data-x=">">const h="cdn."+"example.net";</script>', "cdn.example.net"),
        ("js", "const h=`https://api.example.net/${id}`;", "api.example.net"),
    ],
)
def test_standard_text_forms_and_positions(kind, text, expected):
    mentions = extract(text, kind)
    assert expected in {m.host for m in mentions}
    for mention in mentions:
        assert 0 <= mention.start < mention.end <= len(text)
        assert (mention.line, mention.column) == Positions(text).locate(mention.start)


def test_occurrences_comments_and_code_noise():
    text = 'e.exports; arguments.length; document.createElement; "photo.png"; 0.28; // old-api.example.net'
    mentions = extract(text, "js")
    assert {m.host for m in mentions} == {"photo.png", "old-api.example.net"}
    assert next(m for m in mentions if m.host == "photo.png").host_type == "file_candidate"
    assert next(m for m in mentions if m.host == "old-api.example.net").source == "JS_COMMENT"
    html = "<!-- <script>// old.example.net</script> api&#46;example&#46;net -->"
    assert {m.source for m in extract(html, "html")} == {"HTML_COMMENT"}
    for kind, text in [
        ("text", "a%2eexample%2enet;a%2eexample%2enet"),
        ("js", r'const x="a\u002eexample\u002enet;a\u002eexample\u002enet"'),
    ]:
        occurrences = [m for m in extract(text, kind) if m.host == "a.example.net"]
        assert len(occurrences) == 2
        assert occurrences[0].end < occurrences[1].start


def test_large_literal_chain_has_no_python_recursion_limit():
    text = "const h=" + "+".join(['"a"'] * 1500 + ['".example.net"']) + ";"
    assert "a" * 1500 + ".example.net" not in {m.host for m in extract(text, "js")}
    text = "const h=" + "+".join(['""'] * 1500 + ['"chain.example.net"']) + ";"
    assert "chain.example.net" in {m.host for m in extract(text, "js")}


def test_oracle_exact_occurrences_and_constant_subexpressions():
    raw = "a.example.net a.example.net"
    encoded = "".join(f"%{byte:02X}" for byte in raw.encode())
    mentions = extract(encoded, "text")
    assert [(m.host, m.start, m.end) for m in mentions] == [
        ("a.example.net", 0, 39),
        ("a.example.net", 42, 81),
    ]
    attribute = r"""<button onclick="f('a\u002eexample\u002enet');g('a\u002eexample\u002enet')">x</button>"""
    mentions = [m for m in extract(attribute, "html") if m.host == "a.example.net"]
    assert len(mentions) == 2
    assert all(attribute[m.start : m.end] == r"a\u002eexample\u002enet" for m in mentions)
    assert mentions[0].end < mentions[1].start
    for js in [
        'const h=("api"+".example.net");',
        'const h=("api"+".example.net")+path;',
        r"const h=`api\u002eexample.net/${id}`;",
    ]:
        assert "api.example.net" in {m.host for m in extract(js, "js")}
    assert "xn--fsqu00a.example.com" in {m.host for m in extract("// 例子.example.com", "js")}
    assert "xn--abc-uc0e315c.example.com" in {
        m.host for m in extract("// 例子abc.example.com", "js")
    }
    css = r"<style>a{background:url(https://api\2e example\2e net/a)}</style>"
    assert "api.example.net" in {m.host for m in extract(css, "html")}


def test_comment_cannot_declare_response_encoding():
    from blacklink_discovery.text import decode_body

    body = b"// charset=utf-16\n// api.example.net"
    text, encoding, warning = decode_body(body, "application/javascript")
    assert (encoding, warning) == ("utf-8", "")
    assert "api.example.net" in {m.host for m in extract(text, "js")}


def test_unknown_nested_chain_retains_constant_subexpression():
    text = "const h=" + '(""+' * 1500 + '("api"+".example.net")+unknown' + ")" * 1500 + ";"
    assert "api.example.net" in {m.host for m in extract(text, "js")}


def test_comments_survive_successful_concat_and_member_call():
    text = '("api." + /* hidden.example.net */ "example.com").toString();'
    mentions = extract(text, "js")
    comment = next(m for m in mentions if m.host == "hidden.example.net")
    assert comment.source == "JS_COMMENT"
    assert text[comment.start : comment.end] == "hidden.example.net"
    assert "api.example.com" in {m.host for m in mentions}
    assert "api.example.com" in {
        m.host for m in extract('const h=("api." /* note */)+"example.com";', "js")
    }


def test_bare_idn_with_unicode_marks_is_not_truncated():
    host = "उदाहरण.भारत"
    expected = "xn--p1b6ci4b4b3a.xn--h2brj9c"
    for text, kind in [(host, "text"), ("// " + host, "js"), ("<!-- " + host + " -->", "html")]:
        mentions = extract(text, kind)
        assert {m.host for m in mentions} == {expected}
        assert all(text[m.start : m.end] == host for m in mentions)


def test_large_encoded_text_retains_positions_without_per_character_mapping():
    import tracemalloc

    raw = " " * 1_000_000 + r"api%2eexample%2enet"
    tracemalloc.start()
    try:
        mentions = extract(raw, "text")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert [(m.host, m.start, m.end) for m in mentions] == [
        ("api.example.net", 1_000_000, len(raw))
    ]
    assert peak < 20 * 1024 * 1024


def test_svg_paths_in_js_do_not_become_domains_or_hide_neighboring_mentions():
    text = """const icons = [
        "M12.5 10.2c0-1.487-3.043 2.3 4.5 6.7z",
        "m0 0 1.2.3h-1.2v.4a1.5 2.5 0 0 1 3.5 4.5z",
        "M1e2 -2.5E-1 Q1.2 2.3 4.5 6.7T8.9 10.2Z",
        "M0 0C1.2 3.4 5.6 7.8 9.1 2.3S4.5 6.7 8.9 1.2L3.4 5.6",
    ];
    // legacy.example.net M1.internal 0-1.3
    const host = "M1.internal";
    const short = "M1.2";
    const url = "https://0-1.3/help";
    const ip = "http://192.0.2.1/";
    const concat = "cdn." + "unknownsuffix";
    const note = "M1.internal historical.example.net";
    const escaped = "M0 0L1\\u002e2 3.4";
    const arc = `M0 0a1.5 2.5 0 011.5 2.5z`;
    const joined = "M0 0" + /* retained.example.net */ "L1.2 3.4";
    """
    mentions = extract(text, "js")
    assert {m.host for m in mentions} == {
        "legacy.example.net",
        "m1.internal",
        "0-1.3",
        "cdn.unknownsuffix",
        "historical.example.net",
        "m1.2",
        "192.0.2.1",
        "retained.example.net",
    }
    for host in ("legacy.example.net", "retained.example.net"):
        comment = next(m for m in mentions if m.host == host)
        assert comment.source == "JS_COMMENT"
        assert text[comment.start : comment.end] == host
    assert any(m.host == "0-1.3" and m.source == "JS_STRING" for m in mentions)
    for mention in mentions:
        assert (mention.line, mention.column) == Positions(text).locate(mention.start)


def test_style_and_embedded_svg_syntax_preserves_domain_evidence():
    css = """/* legacy.example.net 1.25em */
    svg.svg-inline--fa, body.toast {width:1.25em; transition:all 0.08s;
      background:url(https://cdn.internal/image); content:"1.25em api.unknown";}
    a[href="https://link.internal"] {color:red}
    @media print {body.nested {width:2.5em} a.second {height:1.25rem}}
    """
    expected = {"legacy.example.net", "1.25em", "cdn.internal", "api.unknown", "link.internal"}
    assert {m.host for m in extract(css, "css")} == expected
    import json

    text = "const style=" + json.dumps(css) + ";\n"
    text += """const cls="tracking-[0.08em]";
    const size="1.25em";
    const url="https://1.25em/path";
    const path="path://M0 0L1.2 3.4z";
    const markup='<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0L1.2 3.4z"/></svg><!-- other.internal -->';
    // saved.internal 1.25em
    """
    mentions = extract(text, "js")
    assert {m.host for m in mentions} == expected | {
        "www.w3.org",
        "other.internal",
        "saved.internal",
    }
    assert any(m.host == "saved.internal" and m.source == "JS_COMMENT" for m in mentions)
    assert {m.host for m in extract('<p style="width:1.25em">body.internal</p>', "html")} == {
        "body.internal"
    }
    for m in mentions:
        assert (m.line, m.column) == Positions(text).locate(m.start)


def test_js_style_values_and_entity_quoted_html_attributes():
    text = """const style={transition:"stroke-dasharray 0.6s ease 0s", margin:"1.6rem 2px"};
    element.style.cssText="width:100%;font-size:14px;line-height:1.6rem;";
    element.style.transition="stroke 0.6s ease";
    const note="legacy.internal 0.6s";
    // history.internal 0.6s
    const url="https://0.6s/path";
    """
    mentions = extract(text, "js")
    assert {m.host for m in mentions} == {"legacy.internal", "history.internal", "0.6s"}
    assert not any(
        m.host in {"0.6s", "1.6rem"} and m.start < text.index("const note") for m in mentions
    )
    raw = '<p style="font-family: &quot;Microsoft YaHei&quot;;font-size:14.6667px;background:url(https://cdn.internal/a)">article.internal</p>'
    for html in (raw, "<script>const markup=" + repr(raw) + ";</script>"):
        mentions = extract(html, "html")
        assert {m.host for m in mentions} == {"cdn.internal", "article.internal"}
        assert all(html[m.start : m.end] == m.host for m in mentions)


def test_component_filenames_and_time_formats_are_not_domain_summary_candidates():
    text = """const file="packages/popover/src/main.vue";
    const component="src/Visitor.tsx";
    const host="https://main.vue/path";
    const format="YYYY-MM-DD[T]HH:mm:ss.SSS[Z]";
    const iso="YYYY-MM-DDTHH:mm:ss.SSSZ";
    const bare="ss.SSS";
    // historic.internal HH:mm:ss.SSS
    """
    mentions = extract(text, "js")
    assert [m.host_type for m in mentions if m.host == "main.vue"] == ["file_candidate", "dns"]
    assert next(m for m in mentions if m.host == "visitor.tsx").host_type == "file_candidate"
    assert not any(m.host == "ss.sss" and m.start < text.index("const bare") for m in mentions)
    assert any(m.host == "ss.sss" and m.source == "JS_COMMENT" for m in mentions)
    assert any(m.host == "ss.sss" and m.source == "JS_STRING" for m in mentions)


def test_code_keys_are_auditable_but_not_domains_and_real_hosts_survive():
    text = """t.$t("menu.SYe"); model.get("itemStyle.color");
    this.dispatch("Form", "el.form.change", "payload.internal");
    node.on("click.menuPanel", handler); Symbol.for("react.element");
    const watch={"$route.path":function(){}};
    const text="[Symbol.iterator]() is a method";
    const hosts=["menu.SYe", "api.unknown", "https://el.form.change/help"];
    http.get("bare.internal");
    // menu.SYe api.unknown
    """
    mentions = extract(text, "js")
    classified = {(m.host, m.host_type) for m in mentions}
    assert {
        ("menu.sye", "syntax_candidate"),
        ("itemstyle.color", "syntax_candidate"),
        ("el.form.change", "syntax_candidate"),
        ("click.menupanel", "syntax_candidate"),
        ("react.element", "syntax_candidate"),
        ("symbol.iterator", "syntax_candidate"),
    } <= classified
    assert {
        ("menu.sye", "dns"),
        ("api.unknown", "dns"),
        ("el.form.change", "dns"),
        ("payload.internal", "dns"),
        ("bare.internal", "dns"),
    } <= classified
    mismatches = [
        (m.host, text[m.start : m.end]) for m in mentions if text[m.start : m.end].lower() != m.host
    ]
    assert mismatches == []


def test_source_map_parses_embedded_code_and_preserves_json_positions():
    import json

    text = json.dumps(
        {
            "sourcesContent": [
                'const emoji="😀"; this.element = 1; // legacy.example.net\nconst h="api.unknown";',
                None,
                'obj.$t("menu.SYe"); const h="https://api.example.net";',
            ]
        }
    )
    mentions = extract(text, "json")
    assert not any(m.host == "this.element" for m in mentions)
    assert next(m for m in mentions if m.host == "legacy.example.net").source == "JS_COMMENT"
    assert next(m for m in mentions if m.host == "menu.sye").host_type == "syntax_candidate"
    assert {m.host for m in mentions} >= {"api.example.net", "api.unknown"}
    assert all(text[m.start : m.end].lower() == m.host for m in mentions)
    assert all((m.line, m.column) == Positions(text).locate(m.start) for m in mentions)
    assert extract('{"sourcesContent":["\\ud800"]}', "json") == []


def test_protocol_relative_host_boundaries_preserve_internal_urls():
    text = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN">
    <script src="chrome-extension://extensionid/inspector.js"></script>
    <a href="//intranet/path">internal</a><a href="http://localhost/">local</a>"""
    mentions = extract(text, "html")
    assert {m.host for m in mentions if m.host_type == "single_label"} == {"intranet", "localhost"}


def test_template_syntax_candidates_do_not_hide_comment_or_url_hosts():
    text = """<p :title="userInfo.cardFN" class="h-0.5 tracking-[0.08em]">{{item.v6}}</p>
    <!-- legacy.example.net 例子.测试 -->
    <a href="https://item.v6/path">domain</a>"""
    mentions = extract(text, "html")
    assert {m.host for m in mentions if m.host_type == "syntax_candidate"} >= {
        "userinfo.cardfn",
        "item.v6",
        "h-0.5",
        "0.08em",
    }
    assert any(m.host == "item.v6" and m.host_type == "dns" for m in mentions)
    assert any(m.host == "legacy.example.net" and m.source == "HTML_COMMENT" for m in mentions)
    assert any(m.host_type == "dns" and m.host.startswith("xn--") for m in mentions)

    component = (
        "<!-- component -->\n<template>"
        + text
        + "</template>\n<script>// saved.internal\n</script>"
    )
    mentions = extract(component, "js")
    assert next(m for m in mentions if m.host == "userinfo.cardfn").host_type == "syntax_candidate"
    assert any(m.host == "saved.internal" and m.source == "JS_COMMENT" for m in mentions)
    assert all((m.line, m.column) == Positions(component).locate(m.start) for m in mentions)


def test_binary_data_urls_do_not_invent_hosts_and_network_urls_keep_positions():
    text = """a {background:url("data:image/png;base64,ABC//5owI/0zYQ//8/K1CMB4j");
    src:url(//cdn.internal/font);}
    /* legacy.example.net */
    b {background:url("data:image/svg+xml,%3Csvg%3Ehttps://svg.example.net/a%3C/svg%3E");}"""
    mentions = extract(text, "css")
    assert {m.host for m in mentions} == {"cdn.internal", "legacy.example.net", "svg.example.net"}
    assert all(text[m.start : m.end] == m.host for m in mentions)
    assert all((m.line, m.column) == Positions(text).locate(m.start) for m in mentions)


def test_known_code_keys_with_public_suffixes_remain_auditable():
    text = """const labels=["$vuetify.pagination.ariaLabel.page","bs.tab","shown.bs.select",
    "progid:DXImageTransform.Microsoft"];
    const attrs={"aria-activedescendant":Object(helper)(menu,"activeTile.id")};
    const files=["CHANGELOG.md"];
    const urls=["https://bs.tab/","https://activeTile.id/","https://changelog.md/"];
    // bs.tab activeTile.id historic.example.net
    """
    mentions = extract(text, "js")
    assert {m.host for m in mentions if m.host_type == "syntax_candidate"} >= {
        "vuetify.pagination.arialabel.page",
        "bs.tab",
        "shown.bs.select",
        "dximagetransform.microsoft",
        "activetile.id",
    }
    assert {m.host for m in mentions if m.host_type == "dns"} >= {
        "bs.tab",
        "activetile.id",
        "changelog.md",
        "historic.example.net",
    }
    assert any(m.host == "changelog.md" and m.host_type == "file_candidate" for m in mentions)
    assert any(
        m.host == "bs.tab" and m.source == "JS_COMMENT" and m.host_type == "dns" for m in mentions
    )
    assert all((m.line, m.column) == Positions(text).locate(m.start) for m in mentions)


def test_delegated_selectors_and_matching_console_labels_are_not_hosts():
    text = """menu.on("click","li.disabled a, .popover-title",handler);
    console.log("res.data",c.data,c.data.total);
    console.log("legacy.example.net",c.data);
    console.log("https://res.data/",c.data);
    const bare="li.disabled";
    // res.data legacy.example.net
    """
    mentions = extract(text, "js")
    assert {m.host for m in mentions if m.host_type == "syntax_candidate"} == {
        "li.disabled",
        "res.data",
    }
    assert {m.host for m in mentions if m.host_type == "dns"} == {
        "li.disabled",
        "res.data",
        "legacy.example.net",
    }
    assert all(text[m.start : m.end] == m.host for m in mentions)


def test_module_ids_replacements_and_code_after_chinese_are_not_hosts():
    text = """__webpack_require__("//Fk");
    href.replace('//rs','/rs');
    const url="//cdn.internal/font";
    // 所有的.img-box元素
    // 所以在window.onload 事件中初始化
    // 例子.测试 legacy.example.net
    """
    mentions = extract(text, "js")
    assert not any(m.host in {"fk", "rs"} for m in mentions)
    assert {m.host for m in mentions if m.host_type == "syntax_candidate"} >= {
        "img-box",
        "window.onload",
    }
    assert {m.host for m in mentions if m.host_type == "dns"} >= {
        "cdn.internal",
        "legacy.example.net",
    }
    assert any(m.host.startswith("xn--") and m.host_type == "dns" for m in mentions)
    assert all(
        text[m.start : m.end].lower() == m.host or m.host.startswith("xn--") for m in mentions
    )

    markup = """<a :href=\"externalLinks.BasicInfoUrl.replace('//rs','/rs')\"></a><!-- legacy.example.net -->"""
    mentions = extract(markup, "html")
    assert not any(m.host == "rs" for m in mentions)
    assert any(m.host == "legacy.example.net" and m.source == "HTML_COMMENT" for m in mentions)


def test_issue_numbers_credits_and_library_fixtures_are_not_domain_summaries():
    text = """【讲座】上图发布 vol.538｜标题
    // thx d.walsh
    new URL("b?a=1","http://a");
    t.exports=!r((function(){var t=new URL("b?a=1&b=2&c=3","http://a")}));
    new URL("https://a@b").username;
    "x" !== new URL("http://x", void 0).host;
    "xn--e1aybc" !== new URL("http://тест").host;
    const real = "https://legacy.example.net/path";
    """
    mentions = extract(text, "js")
    noise = {"vol.538", "d.walsh", "a", "b", "x", "xn--e1aybc"}
    assert not any(m.host in noise and m.host_type == "dns" for m in mentions)
    assert any(m.host == "legacy.example.net" and m.host_type == "dns" for m in mentions)
