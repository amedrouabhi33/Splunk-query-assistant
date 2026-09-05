import json
from pathlib import Path


DATA_FILE = Path(__file__).parent / "data" / "attack_queries.json"


def load_queries():
    with open(DATA_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def find_query(queries, user_input):
    search = user_input.strip().lower()

    # Search by query number
    if search.isdigit():
        number = int(search)

        for query in queries:
            if query["number"] == number:
                return query

    # Search by name
    for query in queries:
        if search == query["name"].lower():
            return query

    # Search by keywords
    for query in queries:
        for keyword in query["keywords"]:
            if search in keyword.lower() or keyword.lower() in search:
                return query

    return None
