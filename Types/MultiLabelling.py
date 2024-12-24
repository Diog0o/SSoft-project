import copy
from Types.MultiLabel import MultiLabel


class MultiLabelling:
    '''
    maps variables to multilabels
    '''
    def __init__(self):
        self.labels: dict[str, MultiLabel] = {}
        # Names which are defined in the program (even if have constant values)
        self.defined_names: set[str] = set()

    def print(self):
        for varname, label in self.labels.items():
            print("VAR", varname)
            label.print()

    def combine(self, other_multi_labelling: "MultiLabelling", are_both_branches: bool = False):
        if are_both_branches:
            self.defined_names = self.defined_names.intersection(other_multi_labelling.defined_names)
        else:
            self.defined_names = self.defined_names.union(other_multi_labelling.defined_names)

        for varname in list(other_multi_labelling.labels.keys()) + list(self.labels.keys()):
            if varname in self.labels and varname in other_multi_labelling.labels:
                self.labels[varname] = self.labels[varname].combine(other_multi_labelling.labels[varname])
            
            # Not in {other.labels} nor {defined_names}
            elif varname in self.labels:
                # already in {self.labels} => no need to add
                if varname not in self.defined_names:
                    self.labels[varname].add_source_to_all(varname, -1)

            # Not in {self.labels} nor {defined_names}
            elif varname in other_multi_labelling.labels:
                # not in {self.labels} => add it
                self.labels[varname] = other_multi_labelling.labels[varname]
                if varname not in self.defined_names:
                    other_multi_labelling.labels[varname].add_source_to_all(varname, -1)
            
        return None

    def is_name_defined(self, name: str) -> bool:
        return name in self.defined_names

    def add_defined_name(self, name: str):
        self.defined_names.add(name)

    def get_multilabel_for_name(self, name: str) -> MultiLabel | None:
        return self.labels.get(name, None)

    def update_multilabel_for_name(self, name: str, multilabel: MultiLabel):
        self.labels[name] = multilabel

        if not self.is_name_defined(name):
            self.add_defined_name(name)

    def deep_copy(self):
        clonedMLL = MultiLabelling()
        for pattern, ml in self.labels.items():
            clonedMLL.labels[pattern] = ml.deep_copy()
        for defined_name in self.defined_names:
            clonedMLL.defined_names.add(defined_name)
        return clonedMLL
    
    def swap(self, multi_labelling: "MultiLabelling"):
        self.defined_names = multi_labelling.defined_names
        self.labels = multi_labelling.labels