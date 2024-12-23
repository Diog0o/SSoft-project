import json
import os
import sys
from astexport import parse, export
from Types.MultiLabelling import MultiLabelling
from Types.Vulnerability import Vulnerabilities

from program_reader import analyse_node
from read_patterns_file import get_policy_from_file

OUTPUT_FOLDER = "output"

def get_ast_from_file(filepath: str) -> dict:
  with open(filepath, "r") as pythonFile:
    ast = parse.parse(pythonFile.read())
    ast = export.export_dict(ast)
  
  with open("target.json", "w") as jsonFile:
    jsonFile.write(json.dumps(ast))

  return ast

if __name__ == "__main__":
  if len(sys.argv) < 3:
    print("[INVALID USAGE]")
    print("Usage: python3 py_analyser.py <slice.py> <patterns.json>")
    exit()

  python_slice_file_path = sys.argv[1]
  patterns_file_path = sys.argv[2]
  output_path = f"{OUTPUT_FOLDER}/{os.path.basename(python_slice_file_path).replace('.py', '.output.json')}"
  
  if not os.path.exists(OUTPUT_FOLDER):
    os.makedirs(OUTPUT_FOLDER)

  ast = get_ast_from_file(python_slice_file_path)
  policy = get_policy_from_file(patterns_file_path)
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