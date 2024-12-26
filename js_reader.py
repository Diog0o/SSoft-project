from Types.MultiLabel import MultiLabel
from Types.MultiLabelling import MultiLabelling
from Types.Policy import Policy
from Types.Vulnerabilities import Vulnerabilities
from utils.combine_labels import combineMultiLabels


# def _get_name(node) -> str:
#     if node["type"] == "MemberExpression":
#         return f"{_get_name(node['object'])}.{node['property']['name']}"
#     elif node["type"] == "CallExpression":
#         if node["callee"]["type"] == "MemberExpression":
#             return f"{_get_name(node['callee']['object'])}.{node['callee']['property']['name']}"
#         else:
#             return node["callee"]["name"]
#     else:
#         return node["name"]
def _get_name(node) -> str:
    if node["type"] == "MemberExpression":
        # Return only the object name for assignment targets
        return _get_name(node['object'])
    elif node["type"] == "CallExpression":
        if node["callee"]["type"] == "MemberExpression":
            return _get_name(node["callee"]["object"])
        else:
            return node["callee"]["name"]
    else:
        return node["name"]

def _get_object_and_property(node) -> tuple[str, str]:
    """Returns (object_name, property_name) for member expressions"""
    if node["type"] == "MemberExpression":
        return (_get_name(node['object']), node['property']['name'])
    return (_get_name(node), None)
def assignment(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, is_aug: bool, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) -> None:
    value = analyse_node(node["right"], policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
    obj_name, prop_name = _get_object_and_property(node["left"])
    
    if value is None:
        multi_labelling.add_defined_name(obj_name)
        return None

    if not is_aug:
        final_multilabel = value
    else:
        final_multilabel = combineMultiLabels(multi_labelling.get_multilabel_for_name(obj_name), value)
        assert final_multilabel is not None

    if implicit_flow_multilabel:
        final_multilabel.combine(implicit_flow_multilabel)

    multi_labelling.update_multilabel_for_name(obj_name, final_multilabel)

    if not while_intermediate_evals and final_multilabel is not None:
        # Check for vulnerabilities on both object and property if property exists
        illegal_flows = policy.determine_illegal_flows(obj_name, final_multilabel)
        if illegal_flows:
            vulnerabilities.save_vulnerabilities(obj_name, node["loc"]["start"]["line"], illegal_flows, policy)
        
        if prop_name:
            illegal_flows = policy.determine_illegal_flows(prop_name, final_multilabel)
            if illegal_flows:
                vulnerabilities.save_vulnerabilities(prop_name, node["loc"]["start"]["line"], illegal_flows, policy)

    return None

def function_call(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) -> MultiLabel | None:
    if node["callee"]["type"] == "MemberExpression":
        obj_name = _get_name(node["callee"]["object"])
        method_name = node["callee"]["property"]["name"]
    else:
        obj_name = None
        method_name = _get_name(node)

    final_multilabel = MultiLabel(policy.patterns)

    if implicit_flow_multilabel:
        for pattern in policy.get_sanitizers_for_name(method_name):
            implicit_flow_multilabel.add_sanitizer(pattern, method_name, node["loc"]["start"]["line"])
        final_multilabel = final_multilabel.combine(implicit_flow_multilabel)

    # Add sources from both object and method
    if obj_name:
        final_multilabel.add_source_to_all(obj_name, node["loc"]["start"]["line"])
        
    for pattern_name in policy.get_sources_for_name(method_name):
        final_multilabel.add_source(pattern_name, method_name, node["loc"]["start"]["line"])

    for arg in node["arguments"]:
        arg_label = analyse_node(arg, policy, multi_labelling, vulnerabilities, False, implicit_flow_multilabel)
        if arg_label:
            final_multilabel = final_multilabel.combine(arg_label)

    for pattern_name in policy.get_sanitizers_for_name(method_name):
        final_multilabel.add_sanitizer(pattern_name, method_name, node["loc"]["start"]["line"])

    return final_multilabel


def binop(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) -> MultiLabel | None:
    left = analyse_node(node["left"], policy, multi_labelling, vulnerabilities, False, implicit_flow_multilabel)
    right = analyse_node(node["right"], policy, multi_labelling, vulnerabilities, False, implicit_flow_multilabel)
    
    # Initialize new multilabel if either side is None
    final_multilabel = MultiLabel(policy.patterns)
    
    if left:
        final_multilabel = final_multilabel.combine(left)
    if right:
        final_multilabel = final_multilabel.combine(right)
        
    return final_multilabel

def unaryop(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) -> MultiLabel | None:
    return analyse_node(node["argument"], policy, multi_labelling, vulnerabilities, False, implicit_flow_multilabel)


def boolop(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) -> MultiLabel | None:
    final_label = MultiLabel(policy.patterns)
    for arg in node["values"]:
        final_label = combineMultiLabels(final_label, analyse_node(arg, policy, multi_labelling, vulnerabilities, False, implicit_flow_multilabel))
    return final_label


def name(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) -> MultiLabel | None:
    varname = _get_name(node)
    name_multilabel = multi_labelling.get_multilabel_for_name(varname)
    final_multilabel = name_multilabel if name_multilabel else MultiLabel(policy.patterns)
    if not multi_labelling.is_name_defined(varname):
        final_multilabel.add_source_to_all(varname, node["loc"]["start"]["line"])
    
    for pattern_name in policy.get_sources_for_name(varname):
        final_multilabel.add_source(pattern_name, varname, node["loc"]["start"]["line"])
    return final_multilabel


def attribute(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) -> MultiLabel | None:
    obj_name, prop_name = _get_object_and_property(node)
    final_multilabel = MultiLabel(policy.patterns)

    # Add object sources
    if not multi_labelling.is_name_defined(obj_name):
        final_multilabel.add_source_to_all(obj_name, node["loc"]["start"]["line"])
    
    # Always track the object name as a source
    final_multilabel.add_source_to_all(obj_name, node["loc"]["start"]["line"])
    
    return final_multilabel


def handle_if(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) -> None:
    test_node_multilabel = analyse_node(node["test"], policy, multi_labelling, vulnerabilities, False, implicit_flow_multilabel)
    if test_node_multilabel:
        test_node_multilabel.convert_implicit()
        if implicit_flow_multilabel:
            test_node_multilabel = combineMultiLabels(test_node_multilabel, implicit_flow_multilabel)
    
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
        for varname in multi_labelling.defined_names:
            if varname in multi_labelling.labels:
                multi_labelling.update_multilabel_for_name(varname, combineMultiLabels(multi_labelling.labels[varname], test_node_multilabel))
            else:
                multi_labelling.update_multilabel_for_name(varname, test_node_multilabel)

    return None


def handle_while(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) -> MultiLabelling:
    test_node_multilabel = analyse_node(node['test'], policy, multi_labelling, vulnerabilities, while_intermediate_evals=False, implicit_flow_multilabel=implicit_flow_multilabel)

    if test_node_multilabel:
        print("here1")
        test_node_multilabel.convert_implicit()
        if implicit_flow_multilabel:
            print("here2")
            test_node_multilabel = test_node_multilabel.combine(implicit_flow_multilabel)

    while_multilabelling = multi_labelling.deep_copy()
    another_clone = multi_labelling.deep_copy()

    # First Iteration should ignore sinks
    for while_node in node['body']['body']:  # Fixed: Accessing the list of statements inside the block
        print("type of while node:")
        print(type(while_node), while_node)
        analyse_node(while_node, policy, while_multilabelling, vulnerabilities, while_intermediate_evals=True, implicit_flow_multilabel=implicit_flow_multilabel)

    # Reversed iteration considers sinks (avoids duplicate vulns)
    for while_node in reversed(node['body']['body']):  # Same fix for reversed iteration
        analyse_node(while_node, policy, while_multilabelling, vulnerabilities, while_intermediate_evals=False, implicit_flow_multilabel=test_node_multilabel)

    # Combine with original because the while block is optional (does not execute if the {test} is false)
    another_clone.combine(while_multilabelling)
    multi_labelling.swap(another_clone)

    if test_node_multilabel is not None:
        for varname in multi_labelling.defined_names:
            if varname in multi_labelling.labels:
                multi_labelling.update_multilabel_for_name(varname, multi_labelling.labels[varname].combine(test_node_multilabel))
            else:
                multi_labelling.update_multilabel_for_name(varname, test_node_multilabel)  

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



# def handle_while(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) -> MultiLabelling:
#     test_node_multilabel = analyse_node(node["test"], policy, multi_labelling, vulnerabilities, False, implicit_flow_multilabel)
#     if test_node_multilabel:
#         test_node_multilabel.convert_implicit()
#         if implicit_flow_multilabel:
#             test_node_multilabel = combineMultiLabels(test_node_multilabel, implicit_flow_multilabel)
#     while_multilabelling = multi_labelling.deep_copy()
#     another_clone = multi_labelling.deep_copy()
#     for while_node in node["body"]:
#         analyse_node(while_node, policy, while_multilabelling, vulnerabilities, True, test_node_multilabel)
#     for while_node in reversed(node["body"]):
#         analyse_node(while_node, policy, while_multilabelling, vulnerabilities, False, test_node_multilabel)
#     another_clone.combine(while_multilabelling)
#     multi_labelling.swap(another_clone)
#     if test_node_multilabel:
#         for varname in multi_labelling.defined_names:
#             if varname in multi_labelling.labels:
#                 multi_labelling.update_multilabel_for_name(varname, combineMultiLabels(multi_labelling.labels[varname], test_node_multilabel))
#             else:
#                 multi_labelling.update_multilabel_for_name(varname, test_node_multilabel)
