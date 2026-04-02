from app.core.scanner import CodeScanner


def _find_vulns(result, vuln_type: str):
    return [v for v in result.vulnerabilities if v.vulnerability_type == vuln_type]


def _extract_taint_flows(vulns):
    flows = []
    for vuln in vulns:
        flows.extend(vuln.metadata.get("taint_flows", []))
    return flows


def test_interprocedural_source_to_sink_trace():
    code = """
def handler(request):
    user_id = request.args.get("id")
    run_query(user_id)

def run_query(uid):
    cursor.execute("SELECT * FROM users WHERE id = " + uid)
"""
    result = CodeScanner().scan_source(code, file_path="sample.py")
    sql_vulns = _find_vulns(result, "sql_injection")
    assert sql_vulns

    taint_flows = _extract_taint_flows(sql_vulns)
    assert taint_flows
    assert any(flow["source_line"] == 3 for flow in taint_flows)
    assert any(flow["sink_line"] == 7 for flow in taint_flows)
    assert any(
        any(step.get("operation") == "call" for step in flow.get("flow_path", []))
        for flow in taint_flows
    )


def test_sanitizer_wrapper_prevents_taint_flow():
    code = """
def clean_int(value):
    return int(value)

def handler(request):
    user_id = clean_int(request.args.get("id"))
    run_query(user_id)

def run_query(uid):
    cursor.execute("SELECT * FROM users WHERE id = " + uid)
"""
    result = CodeScanner().scan_source(code, file_path="sample.py")
    sql_vulns = _find_vulns(result, "sql_injection")
    assert sql_vulns  # syntax detector still flags string concatenation

    taint_flows = _extract_taint_flows(sql_vulns)
    assert taint_flows == []


def test_return_value_propagates_taint_across_functions():
    code = """
def get_payload(request):
    return request.args.get("cmd")

def passthrough(value):
    return value

def handler(request):
    payload = passthrough(get_payload(request))
    eval(payload)
"""
    result = CodeScanner().scan_source(code, file_path="sample.py")
    eval_vulns = _find_vulns(result, "unsafe_eval")
    assert eval_vulns

    taint_flows = _extract_taint_flows(eval_vulns)
    assert taint_flows
    assert any(flow["source_line"] == 3 for flow in taint_flows)
    assert any(flow["sink_line"] == 10 for flow in taint_flows)
