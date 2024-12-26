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
    '''
    Vulnerability[]
    '''
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
                    
                    _sanitizers = label.get_source_sanitizers(src[0], src[1])
                    
                    # Update unsanitized_flows logic for implicit flows
                    has_unsanitized = len(_sanitizers) == 0 or any(len(s) == 0 for s in _sanitizers)
                    is_implicit = label.is_implicit() and pattern.implicit
                    are_there_unsanitized_flows = "yes" if (has_unsanitized or is_implicit) else "no"

                    var_line_number = src[1]
                    if var_line_number == -1:
                        src = (src[0], sink_line_number)

                    # Deduplicate sanitized flows
                    unique_sanitizer_flows = []
                    for flow in _sanitizers:
                        if len(flow) > 0 and list(flow) not in [list(f) for f in unique_sanitizer_flows]:
                            unique_sanitizer_flows.append(flow)

                    new_vuln = _Vulnerability(
                        vulnerability_name,
                        src,
                        (sink, sink_line_number),
                        are_there_unsanitized_flows,
                        [list(s) for s in unique_sanitizer_flows],
                        "yes" if is_implicit else "no"
                    )

                    # Only add if unique vulnerability
                    if not self._vulnerability_exists(new_vuln):
                        self.vulns.append(new_vuln)

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
    
    # def _vulnerability_exists(self, new_vuln: _Vulnerability) -> bool:
    #     for vuln in self.vulns:
    #         if (vuln.source == new_vuln.source and
    #             vuln.sink == new_vuln.sink and
    #             vuln.unsanitized_flows == new_vuln.unsanitized_flows and
    #             vuln.sanitized_flows == new_vuln.sanitized_flows and
    #             vuln.implicit == new_vuln.implicit
    #             ):
    #             return True
    #     return False
    def _vulnerability_exists(self, new_vuln: _Vulnerability) -> bool:
        new_vuln_pattern = new_vuln.vulnerability.split('_')[0]  # Extract the pattern name
        for vuln in self.vulns:
            existing_pattern = vuln.vulnerability.split('_')[0]  # Extract the pattern name for comparison
            if (vuln.source == new_vuln.source and
                vuln.sink == new_vuln.sink and
                vuln.unsanitized_flows == new_vuln.unsanitized_flows and
                vuln.sanitized_flows == new_vuln.sanitized_flows and
                vuln.implicit == new_vuln.implicit and
                existing_pattern == new_vuln_pattern  # Check if patterns are the same
                ):
                return True
        return False

