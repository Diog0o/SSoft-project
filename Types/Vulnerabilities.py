from Types.Vulnerability import Vulnerability
from typing import List
from Types.MultiLabel import MultiLabel
from Types.Policy import Policy
import json

class Vulnerabilities:
    """
    Tracks a list of detected vulnerabilities.
    """
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []

    def add_vulnerabilities(self, sink_name: str, sink_line: int, multi_label: MultiLabel, policy: Policy):
        """
        Analyzes a MultiLabel object and policy to detect and add vulnerabilities.
        """
        for pattern_name, label in multi_label.labels.items():
            if not policy.get_pattern_by_name(pattern_name).is_sink(sink_name):
                continue
            for source in label.get_sources():
                vulnerability_id = f"{pattern_name}_{self.get_next_vulnerability_index(pattern_name)}"

                sanitizers = label.get_source_sanitizers(source[0], source[1])
                has_unsanitized_flows = "yes" if not sanitizers or any(len(path) == 0 for path in sanitizers) else "no"

                source_line = source[1]
                if source_line == -1:
                    # The source is undefined
                    source = (source[0], sink_line)

                print("DETECTED", pattern_name, source, sink_name, sanitizers)
                self.vulnerabilities.append(
                    Vulnerability(
                        vulnerability_id,
                        source,
                        (sink_name, sink_line),
                        has_unsanitized_flows,
                        # Remove empty sanitization paths
                        sanitized_flows=[list(path) for path in sanitizers if path]
                    )
                )

    def export_to_file(self, file_path: str):
        """
        Writes all tracked vulnerabilities to a JSON file.
        """
        output_data = [vuln.to_dict() for vuln in self.vulnerabilities]

        with open(file_path, 'w') as file:
            json.dump(output_data, file, indent=2)

    def get_next_vulnerability_index(self, pattern_name: str) -> int:
        """
        Computes the next available vulnerability index for a given pattern name.
        """
        matching_vulnerabilities = [
            vuln.vulnerability for vuln in self.vulnerabilities 
            if vuln.vulnerability.startswith(f"{pattern_name}_")
        ]
        indices = [int(vuln.split('_')[1]) for vuln in matching_vulnerabilities]
        return max(indices, default=0) + 1