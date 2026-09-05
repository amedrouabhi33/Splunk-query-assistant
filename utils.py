def display_query(query):
    print("\n" + "=" * 70)

    print(f"Query #{query['number']} - {query['name']}")
    print(f"MITRE ATT&CK : {query['mitre']}")
    print(f"Category     : {query['category']}")
    print(f"Log Source   : {query['log_source']}")

    print("=" * 70)

    print("\nDescription:")
    print(query["description"])

    print("\nRecommended Splunk Query:\n")
    print(query["query"])

    print("\nNotes:")
    print(query["notes"])

    print("=" * 70)


def list_queries(queries):
    print("\nAVAILABLE SPLUNK QUERIES")
    print("=" * 70)

    for query in queries:
        print(f"{query['number']:>3}. {query['name']}")

    print("=" * 70)
