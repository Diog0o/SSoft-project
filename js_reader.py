from Types.MultiLabel import MultiLabel
from Types.MultiLabelling import MultiLabelling
from Types.Policy import Policy
from Types.Vulnerabilities import Vulnerabilities
from utils.combine_labels import combineMultiLabels


def _get_name(node) -> str:
    if node["type"] == "MemberExpression":
        return f"{_get_name(node['object'])}.{node['property']['name']}"
    elif node["type"] == "CallExpression":
        if node["callee"]["type"] == "MemberExpression":
            return f"{_get_name(node['callee']['object'])}.{node['callee']['property']['name']}"
        else:
            return node["callee"]["name"]
    else:
        return node["name"]
    

def assignment(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, is_aug: bool, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) -> None:
    value = analyse_node(node["right"], policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
    varname = _get_name(node["left"])
    
    if value is None:
        multi_labelling.add_defined_variable(varname)
        return None
    if not is_aug:
        final_multilabel = value
        
    else:
        final_multilabel = combineMultiLabels(multi_labelling.get_multilabel_for_variable(varname), value)
        assert final_multilabel is not None
    if implicit_flow_multilabel:
        final_multilabel.combine(implicit_flow_multilabel)
    multi_labelling.update_multilabel_for_variable(varname, final_multilabel)
    if not while_intermediate_evals and final_multilabel is not None:
        illegal_flows = policy.determine_illegal_flows(varname, final_multilabel)
        if illegal_flows:
            vulnerabilities.save_vulnerabilities(varname, node["loc"]["start"]["line"], illegal_flows, policy)
    return None


def function_call(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) -> MultiLabel | None:
    # Extract the full function name (e.g., a.b.c)
    function_complete_name = _get_name(node)
    # Extract the function name (e.g., c from a.b.c)
    function_name = function_complete_name.split(".")[-1]
    
    # Initialize the final multilabel with the policy patterns
    final_multilabel = MultiLabel(policy.patterns)

    # Process implicit flow multilabel if it exists
    if implicit_flow_multilabel:
        for pattern in policy.get_sanitizers_by_name(function_name):
            implicit_flow_multilabel.add_sanitizer(pattern, function_name, node["loc"]["start"]["line"])
        final_multilabel = combineMultiLabels(final_multilabel, implicit_flow_multilabel)

    # Check if the function or its parent modules are sources
    for name in function_complete_name.split("."):
        for pattern_name in policy.get_sources_by_name(name):
            final_multilabel.add_source(pattern_name, name, node["loc"]["start"]["line"])

    # Check if any parent in the chain is undefined
    for name in function_complete_name.split(".")[:-1]:
        if not multi_labelling.is_variable_defined(name):
            for pattern in policy.patterns:
                final_multilabel.add_source(pattern.name, name, node["loc"]["start"]["line"])

    # Process arguments of the function call
    for arg in node.get("arguments", []):
        final_multilabel = combineMultiLabels(
            final_multilabel,
            analyse_node(arg, policy, multi_labelling, vulnerabilities, False, implicit_flow_multilabel)
        )
        assert final_multilabel is not None

    # Handle sanitizers associated with this function
    for pattern_name in policy.get_sanitizers_by_name(function_name):
        final_multilabel.add_sanitizer(pattern_name, function_name, node["loc"]["start"]["line"])

    # Determine illegal flows and save vulnerabilities if not in intermediate evaluation
    if not while_intermediate_evals:
        illegal_flows = policy.determine_illegal_flows(function_name, final_multilabel)
        if illegal_flows:
            vulnerabilities.save_vulnerabilities(function_name, node["loc"]["start"]["line"], illegal_flows, policy)

    return final_multilabel



def binop(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) -> MultiLabel | None:
    left = analyse_node(node["left"], policy, multi_labelling, vulnerabilities, False, implicit_flow_multilabel)
    right = analyse_node(node["right"], policy, multi_labelling, vulnerabilities, False, implicit_flow_multilabel)
    return combineMultiLabels(left, right)


def unaryop(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) -> MultiLabel | None:
    return analyse_node(node["argument"], policy, multi_labelling, vulnerabilities, False, implicit_flow_multilabel)


def boolop(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) -> MultiLabel | None:
    final_label = MultiLabel(policy.patterns)
    for arg in node["values"]:
        final_label = combineMultiLabels(final_label, analyse_node(arg, policy, multi_labelling, vulnerabilities, False, implicit_flow_multilabel))
    return final_label


def name(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) -> MultiLabel | None:
    varname = _get_name(node)
    name_multilabel = multi_labelling.get_multilabel_for_variable(varname)
    final_multilabel = name_multilabel if name_multilabel else MultiLabel(policy.patterns)
    if not multi_labelling.is_variable_defined(varname):
        final_multilabel.add_source_to_all(varname, node["loc"]["start"]["line"])
    
    for pattern_name in policy.get_sources_by_name(varname):
        final_multilabel.add_source(pattern_name, varname, node["loc"]["start"]["line"])
    return final_multilabel


def attribute(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) -> MultiLabel | None:
    attribute_complete_name = _get_name(node)
    final_multilabel = multi_labelling.get_multilabel_for_variable(attribute_complete_name)
    if not final_multilabel:
        final_multilabel = MultiLabel(policy.patterns)
    for name in attribute_complete_name.split("."):
        if not multi_labelling.is_variable_defined(name):
            final_multilabel.add_source_to_all(name, node["loc"]["start"]["line"])
            break
    for name in attribute_complete_name.split("."):
        for pattern_name in policy.get_sources_by_name(name):
            final_multilabel.add_source(pattern_name, name, node["loc"]["start"]["line"])
    return final_multilabel


def handle_if(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) -> None:
    test_node_multilabel = analyse_node(node["test"], policy, multi_labelling, vulnerabilities, False, implicit_flow_multilabel)
    
    if test_node_multilabel:
        # Mark all labels from test condition as implicit for patterns that support it
        for pattern_name, label in test_node_multilabel.labels.items():
            if policy.get_pattern_by_name(pattern_name).implicit:
                label.set_implicit(True)
        
        test_node_multilabel.convert_implicit()
        if implicit_flow_multilabel:
            test_node_multilabel = test_node_multilabel.combine(implicit_flow_multilabel)
    
    true_labels = multi_labelling.deep_copy()
    false_labels = multi_labelling.deep_copy()
    
    # When the {test} is True
    for true_node in node["consequent"]["body"]:
        analyse_node(true_node, policy, true_labels, vulnerabilities, False, test_node_multilabel)
    
    # When the {test} is False
    if node.get("alternate") and node["alternate"].get("body"):
        for false_node in node["alternate"]["body"]:
            analyse_node(false_node, policy, false_labels, vulnerabilities, False, test_node_multilabel)
    
    true_labels.combine(false_labels, are_both_branches=True)
    multi_labelling.combine(true_labels)
    
    if test_node_multilabel:
        for varname in multi_labelling.defined_variables:
            if varname in multi_labelling.labels:
                multi_labelling.update_multilabel_for_variable(varname, combineMultiLabels(multi_labelling.labels[varname], test_node_multilabel))
            else:
                multi_labelling.update_multilabel_for_variable(varname, test_node_multilabel)

    return None


def handle_while(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) -> MultiLabelling:
    test_node_multilabel = analyse_node(node['test'], policy, multi_labelling, vulnerabilities, while_intermediate_evals=False, implicit_flow_multilabel=implicit_flow_multilabel)
    
    if test_node_multilabel:
        # Mark all labels from test condition as implicit for patterns that support it
        for pattern_name, label in test_node_multilabel.labels.items():
            if policy.get_pattern_by_name(pattern_name).implicit:
                label.set_implicit(True)
        
        test_node_multilabel.convert_implicit()
        if implicit_flow_multilabel:
            test_node_multilabel = test_node_multilabel.combine(implicit_flow_multilabel)

    while_multilabelling = multi_labelling.deep_copy()
    another_clone = multi_labelling.deep_copy()

    # First Iteration should ignore sinks but propagate implicit flows
    for while_node in node['body']['body']:
        analyse_node(while_node, policy, while_multilabelling, vulnerabilities, 
                    while_intermediate_evals=True, 
                    implicit_flow_multilabel=test_node_multilabel)

    # Reversed iteration considers sinks and implicit flows
    for while_node in reversed(node['body']['body']):
        analyse_node(while_node, policy, while_multilabelling, vulnerabilities, 
                    while_intermediate_evals=False, 
                    implicit_flow_multilabel=test_node_multilabel)

    # Combine with original because the while block is optional
    another_clone.combine(while_multilabelling)
    multi_labelling.swap(another_clone)

    # Propagate implicit flows to all defined variables
    if test_node_multilabel is not None:
        for varname in multi_labelling.defined_variables:
            if varname in multi_labelling.labels:
                combined_label = multi_labelling.labels[varname].combine(test_node_multilabel)
                # Ensure implicit status is preserved after combination
                for pattern_name, label in combined_label.labels.items():
                    if policy.get_pattern_by_name(pattern_name).implicit:
                        label.set_implicit(True)
                multi_labelling.update_multilabel_for_variable(varname, combined_label)
            else:
                multi_labelling.update_multilabel_for_variable(varname, test_node_multilabel)

    return multi_labelling


def module(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) -> MultiLabel | None:
    final_label = MultiLabel(policy.patterns)
    for child_node in node["body"]:
        result = analyse_node(child_node, policy, multi_labelling, vulnerabilities, False, implicit_flow_multilabel)
        final_label = combineMultiLabels(final_label, result)
    return final_label


def expr(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel):
    return analyse_node(node["expression"], policy, multi_labelling, vulnerabilities, False, implicit_flow_multilabel)


def analyse_node(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel):
    match node["type"]:
        case "Program": return module(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
        case "ExpressionStatement": return expr(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
        case "AssignmentExpression": return assignment(node, policy, multi_labelling, vulnerabilities, is_aug=False, while_intermediate_evals=while_intermediate_evals, implicit_flow_multilabel=implicit_flow_multilabel)
        case "Literal": return None
        case "BinaryExpression": return binop(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
        case "UnaryExpression": return unaryop(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
        case "LogicalExpression": return boolop(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
        case "CallExpression": return function_call(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
        case "Identifier": return name(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
        case "MemberExpression": return attribute(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
        case "IfStatement":
            handle_if(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
            return None
        case "WhileStatement":
            handle_while(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
            return None
    return None

