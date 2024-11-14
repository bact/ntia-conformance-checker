from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion


def get_components_without_names(doc):
    """Retrieve SPDX ID of components without names."""
    components_without_names = []
    for package in doc.packages:
        if not package.name:
            components_without_names.append(package.spdx_id)
    return components_without_names


def get_components_without_versions(doc, return_tuples=False):
    """Retrieve name and/or SPDX ID of components without versions."""
    components_without_versions = []
    for package in doc.packages:
        if not package.version:
            if return_tuples:
                components_without_versions.append((package.name, package.spdx_id))
            else:
                components_without_versions.append(package.name)
    return components_without_versions


def get_components_without_suppliers(doc, return_tuples=False):
    """Retrieve name and/or SPDX ID of components without suppliers."""
    components_without_suppliers = []
    for package in doc.packages:
        no_supplier = package.supplier is None or isinstance(
            package.supplier, SpdxNoAssertion
        )
        if no_supplier:
            if return_tuples:
                components_without_suppliers.append((package.name, package.spdx_id))
            else:
                components_without_suppliers.append(package.name)

    return components_without_suppliers


def get_components_without_identifiers(doc):
    """Retrieve name of components without identifiers."""
    return [package.name for package in doc.packages if not package.spdx_id]
