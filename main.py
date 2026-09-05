from queries import load_queries, find_query
from utils import display_query, list_queries


def main():
    queries = load_queries()

    print("""
============================================================
               SPLUNK QUERY ASSISTANT
                    SnipTe$t
============================================================

Search by:
  - Query number
  - Attack name
  - Keyword

Commands:
  list
  exit
============================================================
""")

    while True:
        user_input = input("Search > ").strip()

        if user_input.lower() == "exit":
            print("Goodbye.")
            break

        if user_input.lower() == "list":
            list_queries(queries)
            continue

        result = find_query(queries, user_input)

        if result:
            display_query(result)
        else:
            print("\n[!] No matching query found.\n")


if __name__ == "__main__":
    main()
