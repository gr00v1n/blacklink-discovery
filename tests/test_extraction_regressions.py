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
