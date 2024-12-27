from Types.MultiLabel import MultiLabel


class MultiLabelling:
    '''
    maps variables to multilabels
    '''
    def __init__(self):
        self.labels: dict[str, MultiLabel] = {}
        # Names which are defined in the program (even if have constant values)
        self.defined_variables: set[str] = set()

    def print(self):
        for varname, label in self.labels.items():
            print("VAR", varname)
            label.print()

    def combine(self, other_multi_labelling: "MultiLabelling", are_both_branches: bool = False):
        if are_both_branches:
            self.defined_variables = self.defined_variables.intersection(other_multi_labelling.defined_variables)
        else:
            self.defined_variables = self.defined_variables.union(other_multi_labelling.defined_variables)

        for varname in list(other_multi_labelling.labels.keys()) + list(self.labels.keys()):
            if varname in self.labels and varname in other_multi_labelling.labels:
                self.labels[varname] = self.labels[varname].combine(other_multi_labelling.labels[varname])
            
            # Not in {other.labels} nor {defined_variables}
            elif varname in self.labels:
                # already in {self.labels} => no need to add
                if varname not in self.defined_variables:
                    self.labels[varname].add_source_to_all(varname, -1)

            # Not in {self.labels} nor {defined_variables}
            elif varname in other_multi_labelling.labels:
                # not in {self.labels} => add it
                self.labels[varname] = other_multi_labelling.labels[varname]
                if varname not in self.defined_variables:
                    other_multi_labelling.labels[varname].add_source_to_all(varname, -1)
            
        return None
    
    def add_defined_variable(self, name: str):
        self.defined_variables.add(name)

    def is_variable_defined(self, name: str) -> bool:
        return name in self.defined_variables

    def get_multilabel_for_variable(self, name: str) -> MultiLabel | None:
        return self.labels.get(name, None)

    def update_multilabel_for_variable(self, name: str, multilabel: MultiLabel):
        self.labels[name] = multilabel

        if not self.is_variable_defined(name):
            self.add_defined_variable(name)

        
    def swap(self, multi_labelling: "MultiLabelling"):
        self.defined_variables = multi_labelling.defined_variables
        self.labels = multi_labelling.labels

    def deep_copy(self):
        clonedMLL = MultiLabelling()
        for pattern, ml in self.labels.items():
            clonedMLL.labels[pattern] = ml.deep_copy()
        for defined_name in self.defined_variables:
            clonedMLL.defined_variables.add(defined_name)
        return clonedMLL
