# NTIA Conformance Checker

[![Build Status](https://github.com/spdx/ntia-conformance-checker/workflows/build/badge.svg)](https://github.com/spdx/ntia-conformance-checker/actions)
![CodeQL](https://github.com/spdx/ntia-conformance-checker/actions/workflows/codeql.yml/badge.svg)
[![PyPI version](https://img.shields.io/pypi/v/ntia-conformance-checker.svg)](https://pypi.org/project/ntia-conformance-checker/)
[![Pylint Score](https://img.shields.io/badge/pylint-10/10-green)](https://github.com/spdx/ntia-conformance-checker)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/spdx/ntia-conformance-checker/badge)](https://scorecard.dev/viewer/?uri=github.com/spdx/ntia-conformance-checker)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/10727/badge)](https://www.bestpractices.dev/projects/10727)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.17068669.svg)](https://doi.org/10.5281/zenodo.17068669)

Validate the SPDX SBOM against NTIA, CISA, G7 AI, and other minimum element requirements.

This tool determines whether a [SPDX](https://spdx.dev/) software bill of
materials (SBOM) document contains informational items as required by a
certain specification.

A web-based version of the tool is available (no installation needed) at:
<https://tools.spdx.org/app/ntia_checker/>

## Conformance

Currently, the supported specifications are:

- 2021 National Telecommunications and Information Administration (NTIA)
  ["minimum elements."][ntia]
- 2024 CISA Framing Software Component Transparency (FSCT3)
  ["minimum expected."][fsct3]
- 2026 G7 SBOM for AI ["minimum elements."][g7ai]
  (published by BSI and the G7 AI working group)

### NTIA minimum elements

- Supplier Name
- Component Name
- Version of the Component
- Other Unique Identifiers
- Dependency Relationship
- Author of SBOM Data
- Timestamp

As defined by the NTIA, the minimum elements are
"the essential pieces that support basic SBOM functionality and will serve as
the foundation for an evolving approach to software transparency."

### FSCT3 minimum expected

In addition to information similar to NTIA minimum elements,
FSCT3 requires these Baseline Attributes as part of its "minimum expected":

- License
- Copyright Holder (inside Copyright Notice)

### G7 SBOM for AI minimum elements

The G7 SBOM for AI document organizes minimum elements into seven clusters:

1. **Metadata** — SBOM author, creation timestamp, SBOM generation context
   (SBOM type; SPDX 3 only)
2. **System Level Properties** — component name, version, identifier, supplier
3. **Models** — AI model type, application domain, sensitive data usage,
   model integrity hash, model description, release/build timestamp
   (SPDX 3 `ai_AIPackage`; requires SPDX 3)
4. **Dataset Properties** — dataset type, sensitive data declaration,
   data collection provenance, dataset integrity hash, dataset description
   (SPDX 3 `dataset_DatasetPackage`; requires SPDX 3)
5. **Infrastructure** — no current SPDX 3 mapping (not checked)
6. **Security Properties** — concluded license, dependency relationships
7. **Key Performance Indicators** — no current SPDX 3 mapping (not checked)

For SPDX 2 files, only the standard component fields (clusters 1, 2, 6) are
checked. Clusters 3 and 4 require SPDX 3 with the AI profile or Dataset profile
elements present.

Mappings:

- The mapping of the NTIA elements required data fields to the SPDX 2.3
  specification can be found [here][ntia-spdx23].
- The mapping of FSCT3 Baseline Attributes to ISO/IEC 5962:2021 (SPDX 2.2.1)
  and SPDX 3.0 can be found at Section 2.5 of the FSCT3 document.
- The G7 SBOM for AI minimum elements and their mapping to SPDX 3 fields
  can be found in the [BSI G7 SBOM for AI document][g7ai].
- More comparison of SBOM requirements and their mapping to SPDX can be found
  in [this slide][sbom-reqs] from Takashi Ninjouji of OpenChain Japan SBOM
  Sub-WG, presented at SPDX General Meeting 2024-12-05.

## Installation

This tool requires Python 3.10 or newer.
Its dependencies may require a more recent version of Python.

*Installation Method #1*:
Install from the [Python Package Index (PyPI)][pypi] with `pip`.

```bash
pip install ntia-conformance-checker
```

*Installation Method #2*: Install from local source.
Clone the repo and install dependencies using the following commands:

```bash
git clone https://github.com/spdx/ntia-conformance-checker.git
cd ntia-conformance-checker
pip install .
```

It is recommended to use a virtual environment, especially
if you work with multiple Python versions.
`virtualenv` is a tool for creating isolated Python environments;
it lets you keep a project's dependencies in a single environment
or create separate environments for testing with different Python versions.

## CLI usage

```text
usage: sbomcheck [OPTIONS] PATH

positional arguments:
  PATH                  Filepath for SBOM input

options:
  -h, --help            show this help message and exit
  -s, --sbom-spec {spdx2,spdx3}
                        SBOM specification of the input file; see below for details [default: spdx2]
  -c, --comply {fsct3-min,g7ai,ntia}
                        Compliance standards to check against; see below for details [default: ntia]
  --skip-validation     Skip validation
  -r, --output {html,json,print,quiet}
                        Report output type; see below for details [default: print]
  -o, --output-file PATH
                        Filepath for report output; if omitted, prints to console
  -v, --verbose         Print more information (debug)
  -V, --version         Display version of sbomcheck

choices:
  SBOM specifications (for --sbom-spec):
    spdx2       Software Package Data Exchange (SPDX) 2.x
    spdx3       System Package Data Exchange (SPDX) 3.x

  Compliance standards (for --comply):
    fsct3-min   2024 CISA Framing Software Component Transparency (minimum expectation)
    g7ai        2026 G7 SBOM for AI - Minimum Elements
    ntia        2021 NTIA SBOM Minimum Elements

  Report output types (for --output):
    html        Report in HTML format
    json        Report in JSON format
    print       Print report to console
    quiet       No output unless there are errors

Examples:
  sbomcheck sbom.spdx
  sbomcheck -s spdx3 -c fsct3-min -v sbom.json
  sbomcheck -s spdx3 -c g7ai sbom.json
  sbomcheck sbom.yaml --output json --output-file report.json
```

The user can then analyze a particular file:

```bash
sbomcheck sbom.json
```

To generate the output in machine-readable JSON, run:

```bash
sbomcheck sbom.spdx --output json
```

To analyze an SPDX 3 JSON file, run:

```bash
sbomcheck sbom.json --sbom-spec spdx3
```

To check an AI SBOM (SPDX 3) against the G7 SBOM for AI minimum elements, run:

```bash
sbomcheck -s spdx3 -c g7ai sbom.json
```

Use `-h` for help:

```bash
sbomcheck -h
```

## Usage as a library

`ntia-conformance-checker` can also be imported as a library. For example:

```python
from ntia_conformance_checker import SbomChecker

sbom_checker = SbomChecker("SBOM_filepath")

print(sbom_checker.compliant)
```

To check an AI SBOM (SPDX 3) against the G7 SBOM for AI minimum elements:

```python
from ntia_conformance_checker import G7AIChecker

checker = G7AIChecker("ai_sbom.json", sbom_spec="spdx3")

# Overall compliance
print(checker.compliant)

# Per-cluster compliance (True / False / None if not applicable)
for cluster, result in checker.cluster_compliance.items():
    print(f"{cluster}: {result}")

# AI packages missing required fields
print(checker.ai_packages_without_type_of_model)
print(checker.ai_packages_without_domain)

# Dataset packages missing required fields
print(checker.dataset_packages_without_dataset_type)
```

Alternatively, using the `SbomChecker` factory:

```python
from ntia_conformance_checker import SbomChecker

checker = SbomChecker("ai_sbom.json", sbom_spec="spdx3", compliance="g7ai")
print(checker.compliant)
```

See the API documentation at:
<https://spdx.github.io/ntia-conformance-checker/>

Additional properties and methods can be found in `BaseChecker` class
at [`base_checker.py`](ntia_conformance_checker/base_checker.py).
AI- and dataset-specific properties shared across AI-focused checkers are in
`BaseAIDataChecker` at
[`base_ai_data_checker.py`](ntia_conformance_checker/base_ai_data_checker.py).
Specific properties and methods for a particular specification can be found
at the checker for that specification. For example, `NTIAChecker` class
at [`ntia_checker.py`](ntia_conformance_checker/ntia_checker.py),
or `G7AIChecker` at [`g7ai_checker.py`](ntia_conformance_checker/g7ai_checker.py).

## Online usage

With the SPDX Online Tool, you can check the SBOM conformance without the need
to install the Python package.

Go to this page: <https://tools.spdx.org/app/ntia_checker/>.

## HTML output

The HTML output is organized into four distinct div blocks,
each with a specific CSS class for easy styling and targeting:

- Errors (parsing, etc.): `<div class="conformance-err">`
- Conformance results: `<div class="conformance-res">`
- Components missing required information: `<div class="conformance-mis">`
- Detailed validation information: `<div class="conformance-val">`

## History

- The project is the result of an initial [Google Summer of Code (GSoC)][gsoc]
  [contribution in 2022][gsoc2022] by [@linynjosh][].
- SPDX 3 support and improved FSCT3 checker, available in [v4.0.0][],
  are [GSoC 2025 contribution][gsoc2025] by [@bact][].
- The project is maintained by a community of SPDX adopters and enthusiasts.
- See SPDX's participation in Google Summer of Code (GSoC):
  <https://github.com/spdx/GSoC>.

[gsoc]: https://summerofcode.withgoogle.com/
[gsoc2022]: https://github.com/spdx/ntia-conformance-checker/wiki/Project-Origin
[@linynjosh]: https://github.com/linynjosh
[v4.0.0]: https://github.com/spdx/ntia-conformance-checker/blob/main/CHANGELOG.md#400---2025-09-05
[gsoc2025]: https://github.com/spdx/ntia-conformance-checker/wiki/Adding-SPDX-3.0-Support
[@bact]: https://github.com/bact

## License

[Apache-2.0](./LICENSE)

## Dependencies

- [spdx-tools](https://pypi.org/project/spdx-tools/)
  used for parsing the SPDX 2 SBOM.
- [spdx-python-model](https://pypi.org/project/spdx-python-model/)
  used for parsing the SPDX 3 SBOM.

## Support

- Submit issues, questions or feedback at
  <https://github.com/spdx/ntia-conformance-checker/issues>
- Join the discussion on <https://lists.spdx.org/g/spdx-tech> and
  <https://spdx.dev/participate/tech/>

## Contributing

Contributions are very welcome! See [CONTRIBUTING.md](./CONTRIBUTING.md)
for instructions on how to contribute to the codebase.

## Further help

Check out the [frequently asked questions](./FAQ.md) document.

[ntia]: https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom
[ntia-spdx23]: https://spdx.github.io/spdx-spec/v2.3/how-to-use/#k22-mapping-ntia-minimum-elements-to-spdx-fields
[fsct3]: https://www.cisa.gov/resources-tools/resources/framing-software-component-transparency-2024
[g7ai]: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/KI/SBOM-for-AI_minimum-elements.html
[sbom-reqs]: https://drive.google.com/file/d/14HZGYD7pSSWEmtaHZzWrzPhxCXaCnloJ/view
[pypi]: https://pypi.org/project/ntia-conformance-checker/
