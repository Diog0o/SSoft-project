import json
import os
import sys
import esprima  # Esprima for JavaScript parsing
from Types.MultiLabelling import MultiLabelling
from Types.Vulnerabilities import Vulnerabilities
#from program_reader import analyse_node
from pattern_reader import read_pattern

# Directory to store output files
OUTPUT_DIR = "output"

def parse_js_file(filepath: str) -> dict:
    """
    Parse a JavaScript file into an AST using Esprima.
    The AST is returned as a dictionary for easy manipulation.
    """
    try:
        with open(filepath, "r") as file:
            js_code = file.read()
            ast = esprima.parseScript(js_code, loc=True, comment=True)
        # Save AST to a JSON file for inspection
        with open("parsed_ast.json", "w") as debug_file:
            json.dump(ast.toDict(), debug_file, indent=2)
        return ast.toDict()
    except Exception as e:
        print(f"Error while parsing the JavaScript file: {e}")
        sys.exit(1)

def display_policy_details(policy):
    """
    Display details of the patterns from the provided policy object.
    """
    print(" [PATTERNS]")
    print()
    for pattern in policy.patterns:
        print(f" - Pattern Name: {pattern.name}")
        print(f"   Sources: {pattern.sources}")
        print(f"   Sanitizers: {pattern.sanitizers}")
        print(f"   Sinks: {pattern.sinks}")
        print(f"   Implicit Rules: {pattern.implicit}")
    print()

def display_analysis_results(multi_labelling, vulnerabilities):
    """
    Display the results of the analysis including multi-labelling details and detected vulnerabilities.
    """
    print("[ANALYSIS RESULTS]")
    print("\n [MULTI-LABELLING]")
    for variable, multi_label in multi_labelling.labels.items():
        print(f" - Variable: {variable}")
        for pattern_name, label in multi_label.labels.items():
            print(f"   Pattern: {pattern_name} | {label.get_sources_and_sanitizers()}")
    print()

    print("----------------------------------")
    print(" [DETECTED VULNERABILITIES]")
    for vulnerability in vulnerabilities.vulns:
        print(f" - {vulnerability}\n")

def ensure_output_directory():
    """
    Create the output directory if it doesn't already exist.
    """
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

def main():
    if len(sys.argv) < 3:
        print("[ERROR] Missing required arguments.")
        print("Usage: python3 javascript_parser.py <javascript_file.js> <patterns.json>")
        sys.exit(1)

    js_file = sys.argv[1]
    patterns_file = sys.argv[2]
    output_file = os.path.join(OUTPUT_DIR, f"{os.path.basename(js_file).replace('.js', '.output.json')}")

    ensure_output_directory()

    print("[INFO] Parsing JavaScript file...")
    js_ast = parse_js_file(js_file)

    print("[INFO] Loading policy from patterns file...")
    policy = read_pattern(patterns_file)

    multi_labelling = MultiLabelling()
    vulnerabilities = Vulnerabilities()

    # print("[INFO] Starting analysis...")
    # analyse_node(
    #     node=js_ast,
    #     policy=policy,
    #     multi_labelling=multi_labelling,
    #     vulnerabilities=vulnerabilities,
    #     while_intermediate_evals=False,
    #     implicit_flow_multilabel=None
    # )

    # print("[INFO] Analysis complete. Generating output...")

    # # Display results
    # display_policy_details(policy)
    # display_analysis_results(multi_labelling, vulnerabilities)

    # # Save vulnerabilities to file
    # vulnerabilities.write_to_file(output_file)
    # print(f"[INFO] Vulnerabilities written to '{output_file}'")

if __name__ == "__main__":
    main()