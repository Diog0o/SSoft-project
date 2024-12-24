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

class Vulnerabilities:
    '''
    Vulnerability[]
    '''
    def __init__(self):
        self.vulns: list[_Vulnerability] = []    

    def save_vulnerabilities(self, sink_name: str, sink_line_number: int, multilabel: MultiLabel, policy: Policy):
        for pattern_name, label in multilabel.labels.items():
            for sink in sink_name.split('.'):
                if not policy.get_pattern_by_name(pattern_name).is_sink(sink): continue
                for src in label.get_sources():
                    vulnerability_name = f"{pattern_name}_{self.get_next_vuln_index(pattern_name)}"

                    _sanitizers = label.get_source_sanitizers(src[0], src[1])
                    are_there_unsanitized_flows = "yes" if len(_sanitizers) == 0 or any(len(s) == 0 for s in _sanitizers) else "no"

                    var_line_number = src[1]
                    if var_line_number == -1:
                        # The source is undefined
                        src = (src[0], sink_line_number)

                    print("SAVE", pattern_name, src, sink_name, sink, _sanitizers)
                    self.vulns.append(
                        _Vulnerability(
                            vulnerability_name,
                            src,
                            (sink, sink_line_number),
                            are_there_unsanitized_flows,
                            # Remove empty sanitization paths
                            sanitized_flows=[list(s) for s in _sanitizers if len(s) > 0]
                        )
                    )

    def write_to_file(self, path: str):
        output = []
        for vuln in self.vulns:
            vulnerability_obj = {
                "vulnerability": vuln.vulnerability,
                "source": vuln.source,
                "sink": vuln.sink,
                "unsanitized_flows": vuln.unsanitized_flows,
                "sanitized_flows": vuln.sanitized_flows
            }
            output.append(vulnerability_obj)

        with open(path, 'w') as file:
            json.dump(output, file, indent=2)

    def get_next_vuln_index(self, pattern_name: str) -> int:
        filtered_elements = [element.vulnerability for element in self.vulns if element.vulnerability.startswith(f"{pattern_name}_")]
        numbers = [int(element.split('_')[1]) for element in filtered_elements]
        max_number = max(numbers, default=0)
        return max_number + 1
