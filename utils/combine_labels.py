from Types.MultiLabel import MultiLabel

def combineMultiLabels(l1: MultiLabel | None, l2: MultiLabel | None) -> MultiLabel | None:
  if l1 is None and l2 is None:
    raise Exception("Called combineLabels with 2 Nones")
  elif l1 is not None and l2 is not None:
    return l1.combine(l2)
  elif l2 is None:
    return l1
  elif l1 is None:
    return l2