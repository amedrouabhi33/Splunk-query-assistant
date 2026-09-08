def display_query(query):
    print("\n" + "=" * 78)
    print(f"Query #{query['number']} - {query['name']}")
    print("=" * 78)

    print("\n[MITRE ATT&CK]")
    print(f"Technique ID : {query.get('mitre_id', 'N/A')}")
    print(f"Technique    : {query.get('mitre_name', 'N/A')}")
    print(f"Tactic       : {query.get('mitre_tactic', 'N/A')}")
    print(f"MITRE URL    : {query.get('mitre_url', 'N/A')}")

    print("\n[DETECTION INFORMATION]")
    print(f"Severity     : {query.get('severity', 'N/A')}")
    print(f"Category     : {query.get('category', 'N/A')}")
    print(f"Log Source   : {query.get('log_source', 'N/A')}")

    print("\nDescription:")
    print(query.get("description", "N/A"))

    print("\nRequired Fields:")
    for field in query.get("required_fields", []):
        print(f"  - {field}")

    print("\n[SPLUNK QUERY]\n")
    print(query.get("query", "N/A"))

    print("\n[INVESTIGATION STEPS]")
    for step in query.get("investigation", []):
        print(f"  - {step}")

    print("\n[POSSIBLE FALSE POSITIVES]")
    for item in query.get("false_positives", []):
        print(f"  - {item}")

    print("\n[RECOMMENDED RESPONSE]")
    for step in query.get("response", []):
        print(f"  - {step}")

    print("\n[NOTES]")
    print(query.get("notes", "N/A"))
    print("=" * 78)


def list_queries(queries):
    print("\nAVAILABLE SPLUNK QUERIES")
    print("=" * 78)
    for query in queries:
        print(f"{query['number']:>3}. {query['name']}")
    print("=" * 78)
