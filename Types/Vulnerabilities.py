from Types.Vulnerability import Vulnerability
from typing import List
from Types.MultiLabel import MultiLabel
from Types.Policy import Policy
import json

class Vulnerabilities:
    '''
    List of Vulnerability objects.
    '''
    def __init__(self):
        self.vulns: List[Vulnerability] = []

    def save_vulnerabilities(self, sink_name: str, sink_line_number: int, multilabel: MultiLabel, policy: Policy):
        for pattern_name, label in multilabel.labels.items():
          if not policy.get_pattern_by_name(pattern_name).is_sink(sink_name): 
            continue
          for src in label.get_sources():
            vulnerability_name = f"{pattern_name}_{self.get_next_vuln_index(pattern_name)}"

            _sanitizers = label.get_source_sanitizers(src[0], src[1])
            are_there_unsanitized_flows = "yes" if len(_sanitizers) == 0 or any(len(s) == 0 for s in _sanitizers) else "no"

            var_line_number = src[1]
            if var_line_number == -1:
                # The source is undefined
                src = (src[0], sink_line_number)

            print("SAVE", pattern_name, src, sink_name, sink_name, _sanitizers)
            self.vulns.append(
                Vulnerability(
                    vulnerability_name,
                    src,
                    (sink_name, sink_line_number),
                    are_there_unsanitized_flows,
                    # Remove empty sanitization paths
                    sanitized_flows=[list(s) for s in _sanitizers if len(s) > 0]
                      )
                  )

    def write_to_file(self, path: str):
        """
        Write all stored vulnerabilities to a JSON file.
        """
        output = [vuln.to_dict() for vuln in self.vulns]

        with open(path, 'w') as file:
            json.dump(output, file, indent=2)

    def get_next_vuln_index(self, pattern_name: str) -> int:
        """
        Get the next available vulnerability index for a given pattern name.
        """
        filtered_elements = [v.vulnerability for v in self.vulns if v.vulnerability.startswith(f"{pattern_name}_")]
        numbers = [int(e.split('_')[1]) for e in filtered_elements]
        max_number = max(numbers, default=0)
        return max_number + 1