# Contributing

Thank you for your interest in `ntia-conformance-checker`. The project is open-source software, and bug reports, suggestions, and
most especially patches are welcome.

## Issues

`ntia-conformance-checker` has a [project page on GitHub](https://github.com/spdx/ntia-conformance-checker/) where you
can [create an issue](https://github.com/spdx/ntia-conformance-checker/issues/new) to report a bug, make a suggestion, or propose a
substantial change or improvement. You may also wish to contact the SPDX working group technical team through its
mailing list, [spdx-tech@lists.spdx.org](mailto:spdx-tech@lists.spdx.org).

If you would like to work on a fix for any issue, please assign the issue to yourself or write a comment indicating your
intention prior to creating a patch.

## Development process

We use the GitHub flow that is described here: https://guides.github.com/introduction/flow/

Here's the process to make changes to the codebase:

1. Find or [file an issue](#issues) you'd like to address. Every change should be made to fix or close an issue. Please
   try to keep issues reasonably small, focusing on one aspect, or split off sub-issues if possible. Large pull requests
   that fix many things at the same time tend to cause a lot of conflicts.

2. Review [open pull requests](https://github.com/spdx/ntia-conformance-checker/pulls) before committing time to a substantial
   revision. Work along similar lines may already be in progress.

3. Create a new branch:
   ```sh
   git checkout -b fix-or-improve-something
   ```
4. Make some changes and commit them to the branch:
   ```sh
   git commit --signoff -m 'description of my changes'
   ```

   #### Licensing

   Please sign off in each of your commits that you license your contributions under the terms
   of [the Developer Certificate of Origin](https://developercertificate.org/). Git has utilities for signing off on
   commits: `git commit -s` or `--signoff` signs a current commit, and `git rebase --signoff <revision-range>`
   retroactively signs a range of past commits.

5. Test your changes:
   ```sh
   python setup.py test # in the repo root
   ```
   You may use other test runners, such as `pytest` or `nose` at your preference.
6. Format your changes with [`black`](https://github.com/psf/black) and [`pylint`](https://github.com/pylint-dev/pylint).
7. Push the branch to your fork on GitHub:
   ```sh
   git push origin fix-or-improve-something
   ```
8. Make a pull request on GitHub.
9. Continue making more changes and commits on the branch, with `git commit --signoff` and `git push`.
10. When done, write a comment on the PR asking for a code review.
11. Some other developer will review your changes and accept your PR. The merge should be done with `rebase`, if
    possible, or with `squash`.
12. The temporary branch on GitHub should be deleted (there is a button for deleting it).
13. Delete the local branch as well:
    ```sh
    git checkout master
    git pull -p
    git branch -a
    git branch -d fix-or-improve-something
    ```

## How to run tests

The tests framework is using [pytest][]:

```sh
pip install pytest
pytest -vvs
```

[pytest]: https://docs.pytest.org/

## How to generate API documentation

This package uses [Sphinx][] to generate API documentation from
Python docstrings.

```sh
sphinx-apidoc -o docs/ ntia_conformance_checker/
cd docs
make html
```

[sphinx]: https://www.sphinx-doc.org/
