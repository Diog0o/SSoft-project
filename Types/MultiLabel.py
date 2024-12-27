import copy
from Types.Label import Label
from Types.Pattern import Pattern


class MultiLabel:
    '''
    Maps {Labels} to {Patterns}

    labels => { "pattern1": Label, "pattern2": Label, ... }
    patterns => { "pattern1": Pattern, "pattern2": Pattern, ... }
    '''
    def __init__(self, patterns: list[Pattern]):
        # key: pattern name
        # value: Label
        self.labels: dict[str, Label] = {}
        for pattern in patterns:
            self.labels[pattern.name] = Label()

        self.patterns: dict[str, Pattern] = {}
        for pattern in patterns:
            self.patterns[pattern.name] = pattern
    
    def print(self):
        print("-- PRINT --")
        for pattern_name, label in self.labels.items():
            print(pattern_name, ":", label.sources_sanitizers_dict)
        print("-- END PRINT --")

    def add_label(self, pattern_name: str, label: Label):
        self.labels[pattern_name] = label
    
    def update_label(self, pattern: str, label: Label, if_implicit: bool = False):
        if if_implicit:
            if self.patterns[pattern].implicit:
                self.labels[pattern] = label
                self.labels[pattern].set_implicit(True)
        else:
            self.labels[pattern] = label

    def add_source(self, pattern_name: str, source: str, line_number: int):
        self.labels[pattern_name].add_source((source, line_number))

    def add_sanitizer(self, pattern_name, sanitizer: str, line_number: int):
        if pattern_name in self.labels:
            self.labels[pattern_name].add_sanitizer(sanitizer, line_number)

    # To use when an undefined {name} impacts a MultiLabel
    def add_source_to_all(self, source: str, line_number: int):
        for pattern_name in self.labels.keys():
            self.labels[pattern_name].add_source((source, line_number))


    def convert_implicit(self):
        for pattern_name, label in self.labels.items():
            if not self.patterns[pattern_name].implicit:
                # Reset Labels for {patterns} that don't want to include implicit flows
                self.labels[pattern_name] = Label()
            else:
                # Mark existing labels as implicit for patterns that support it
                label.set_implicit(True)

    def get_sources(self, pattern_name):
        if pattern_name in self.labels:
            return self.labels[pattern_name].get_sources_and_sanitizers().keys()
        return set()
    
    def deep_copy(self):
        clonedML = MultiLabel(list(self.patterns.values()))
        for pattern_name, label in self.labels.items():
            clonedML.labels[pattern_name] = label.deep_copy()
        return clonedML

    def combine(self, other_multi_label: "MultiLabel"):
        combined_multi_label: MultiLabel = other_multi_label.deep_copy()

        for pattern_name, label in self.labels.items():
            combined_multi_label.labels[pattern_name] = label.combine(other_multi_label.labels[pattern_name])

        return combined_multi_label