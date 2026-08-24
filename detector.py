import re
PATTERNS=[r"sql syntax.*mysql",r"warning.*mysql",r"mysql_fetch",r"mysqli_",r"pdoexception",r"sqlstate",r"postgresql.*error",r"pg_query",r"sqlite.*error",r"sqlite3.*error",r"ora-\d{5}",r"oracle.*error",r"microsoft sql server",r"odbc sql server driver",r"unclosed quotation mark",r"syntax error.*near"]
def analyze_response(text):
    return [p for p in PATTERNS if re.search(p,text.lower())]
def compare_responses(base,current):
    ratio=abs(current['length']-base['length'])/base['length'] if base['length'] else (1.0 if current['length'] else 0.0)
    changed=base['status']!=current['status']
    return {'baseline_status':base['status'],'current_status':current['status'],'length_difference_ratio':ratio,'status_changed':changed,'strong_change':changed or ratio>=.5}
