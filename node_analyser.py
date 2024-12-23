


def analyse_node(node, policy: Policy, multi_labelling: MultiLabelling, vulnerabilities: Vulnerabilities, while_intermediate_evals: bool, implicit_flow_multilabel: MultiLabel | None) ->  MultiLabel | None:
    match (node["ast_type"]):
      case "Module": return module(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
      
      # Expressions
      case "Expr": return expr(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
      case "Assign": return assignment(node, policy, multi_labelling, vulnerabilities, is_aug=False, while_intermediate_evals=while_intermediate_evals, implicit_flow_multilabel=implicit_flow_multilabel)
      case "AugAssign": return assignment(node, policy, multi_labelling, vulnerabilities, is_aug=True, while_intermediate_evals=while_intermediate_evals, implicit_flow_multilabel=implicit_flow_multilabel)
      case "Constant": return None
      case "BinOp": return binop(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
      case "UnaryOp": return unaryop(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
      case "BoolOp": return boolop(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
      case "Compare": return compare(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
      case "Call": return function_call(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
      case "Name": return name(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
      case "Attribute": return attribute(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
      
      # Statements
      case "If": 
        handle_if(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
        return None
      case "While": 
        handle_while(node, policy, multi_labelling, vulnerabilities, while_intermediate_evals, implicit_flow_multilabel)
        return None
      
    return None