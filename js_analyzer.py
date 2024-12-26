import json
import os
import sys
import esprima  # Esprima for JavaScript parsing
from Types.MultiLabelling import MultiLabelling
from Types.Vulnerabilities import Vulnerabilities
from js_reader import analyse_node
from pattern_reader import read_pattern

OUTPUT_FOLDER = "output"

def parse_js_file(filepath: str) -> dict:
    """
    Parse a JavaScript file into an AST using Esprima.
    The AST is returned as a dictionary for easy manipulation.
    """
    try:
        with open(filepath, "r") as file:
            js_code = file.read().strip()
            ast = esprima.parseScript(js_code, loc=True, comment=True)
        # Save AST to a JSON file for inspection
        with open("parsed_ast.json", "w") as debug_file:
            json.dump(ast.toDict(), debug_file, indent=2)
        return ast.toDict()
    except Exception as e:
        print(f"Error while parsing the JavaScript file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("[INVALID USAGE]")
        print("Usage: python3 js_analyzer.py <slice.js> <patterns.json>")
        exit()

    js_slice_file_path = sys.argv[1]
    patterns_file_path = sys.argv[2]
    output_path = f"{OUTPUT_FOLDER}/{os.path.basename(js_slice_file_path).replace('.js', '.output.json')}"
    
    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)

    ast = parse_js_file(js_slice_file_path)
    policy = read_pattern(patterns_file_path)
    multi_labelling = MultiLabelling()
    vulnerabilities = Vulnerabilities()

    analyse_node(
        ast,
        policy,
        multi_labelling,
        vulnerabilities,
        while_intermediate_evals=False,
        implicit_flow_multilabel=None
    )

    print(" [PATTERNS]")
    print()
    for pattern in policy.patterns:
        print(f" {pattern.name}")
        print(f"  sources: {pattern.sources}")
        print(f"  sanitizers: {pattern.sanitizers}")
        print(f"  sinks: {pattern.sinks}")
        print(f"  implicit: {pattern.implicit}")

    print()
    print("[ANALYSIS COMPLETE]")
    print()

    print(" [MULTI-LABELLING]")
    for varname, multi_label in multi_labelling.labels.items():
        print(f"  Variable: {varname}")
        
        for pattern_name, label in multi_label.labels.items():
            print(f"   Pattern: {pattern_name} | {label.get_sources_and_sanitizers()}")

    print()
    print("----------------------------------")

    print(" [VULNERABILITIES]")
    for vulnerability in vulnerabilities.vulns:
        print(f"   {vulnerability}\n")

    print()
    vulnerabilities.write_to_file(output_path)
    print(f"Vulnerabilities written to '{output_path}'")