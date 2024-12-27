from dataclasses import dataclass
import json
from Types.MultiLabel import MultiLabel
from Types.Policy import Policy

@dataclass
class _Vulnerability:
    vulnerability: str
    source: tuple[str, int]
    sink: tuple[str, int]
    unsanitized_flows: str
    sanitized_flows: list[list[tuple[str, int]]]
    implicit: str

class Vulnerabilities:
    def __init__(self):
        self.vulns: list[_Vulnerability] = []    

    def save_vulnerabilities(self, sink_name: str, sink_line_number: int, multilabel: MultiLabel, policy: Policy):
        for pattern_name, label in multilabel.labels.items():
            pattern = policy.get_pattern_by_name(pattern_name)
            for sink in sink_name.split('.'):
                if not pattern.is_sink(sink):
                    continue
                for src in label.get_sources():
                    vulnerability_name = f"{pattern_name}_{self.get_next_vuln_index(pattern_name)}"
                    
                    _sanitizers = label.get_sanitizers_of_source(src[0], src[1])
                    
                    # Normalize sanitized flows first
                    unique_sanitizer_flows = []
                    for flow in _sanitizers:
                        if len(flow) > 0:  # Only include non-empty flows
                            sorted_flow = sorted(list(flow), key=lambda x: (x[1], x[0]))
                            if sorted_flow not in unique_sanitizer_flows:
                                unique_sanitizer_flows.append(sorted_flow)
                    
                    # Sort the flows themselves
                    unique_sanitizer_flows.sort(key=lambda x: tuple((san[1], san[0]) for san in x))
                    
                    # Determine if there are unsanitized flows
                    is_implicit = label.is_implicit() and pattern.implicit
                    has_unsanitized = len(_sanitizers) == 0 or any(len(s) == 0 for s in _sanitizers)
                    
                    # For implicit flows, if there's at least one sanitizer, it's considered sanitized
                    if is_implicit and unique_sanitizer_flows:
                        are_there_unsanitized_flows = "no"
                    else:
                        are_there_unsanitized_flows = "yes" if has_unsanitized else "no"

                    var_line_number = src[1]
                    if var_line_number == -1:
                        src = (src[0], sink_line_number)

                    new_vuln = _Vulnerability(
                        vulnerability_name,
                        src,
                        (sink, sink_line_number),
                        are_there_unsanitized_flows,
                        unique_sanitizer_flows,
                        "yes" if is_implicit else "no"
                    )

                    if not self._vulnerability_exists(new_vuln):
                        self.vulns.append(new_vuln)

    def _vulnerability_exists(self, new_vuln: _Vulnerability) -> bool:
        # Extract pattern name (e.g., "A" from "A_1")
        new_pattern = new_vuln.vulnerability.split('_')[0]
        
        for vuln in self.vulns:
            existing_pattern = vuln.vulnerability.split('_')[0]
            
            # Compare all fields except vulnerability name
            if (vuln.source == new_vuln.source and
                vuln.sink == new_vuln.sink and
                vuln.unsanitized_flows == new_vuln.unsanitized_flows and
                sorted([tuple(flow) for flow in vuln.sanitized_flows]) == sorted([tuple(flow) for flow in new_vuln.sanitized_flows]) and
                vuln.implicit == new_vuln.implicit and
                existing_pattern == new_pattern):  # Check if patterns match
                return True
        return False

    def write_to_file(self, path: str):
        output = []
        for vuln in self.vulns:
            vulnerability_obj = {
                "vulnerability": vuln.vulnerability,
                "source": vuln.source,
                "sink": vuln.sink,
                "unsanitized_flows": vuln.unsanitized_flows,
                "sanitized_flows": vuln.sanitized_flows,
                "implicit": vuln.implicit
            }
            output.append(vulnerability_obj)

        with open(path, 'w') as file:
            json.dump(output, file, indent=2)

    def get_next_vuln_index(self, pattern_name: str) -> int:
        filtered_elements = [element.vulnerability for element in self.vulns if element.vulnerability.startswith(f"{pattern_name}_")]
        numbers = [int(element.split('_')[1]) for element in filtered_elements]
        max_number = max(numbers, default=0)
        return max_number + 1