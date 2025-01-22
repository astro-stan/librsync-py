# Contributing to librsync-py

First off, thanks for taking the time to contribute! ❤️

All types of contributions are encouraged and valued. See the [Table of Contents](#table-of-contents) for different ways to help and details about how this project handles them. Please make sure to read the relevant section before making your contribution. It will make it a lot easier for the maintainers and smooth out the experience for all involved. The community looks forward to your contributions. 🎉

If you like the project, but just don't have time to contribute, that's fine. There are other easy ways to support the project and show your appreciation:

- Star the project
- Tweet about it
- Refer this project in your project's readme
- Mention the project at local meetups and tell your friends/colleagues

## Table Of Contents

* [Code of Conduct](#code-of-conduct)
* [I Want To Contribute](#i-want-to-contribute)
    + [Setting Up a Developer Environment](#setting-up-a-developer-environment)
        - [Prerequisites](#prerequisites)
        - [Running the unit tests](#running-the-unit-tests)
        - [Building the wheels and sdist](#building-the-wheels-and-sdist)
        - [Other Commands](#other-commands)
    + [Submitting a Pull Request](#submitting-a-pull-request)
        - [How To Submit a Good Pull Request](#how-to-submit-a-good-pull-request)
    + [Reporting Bugs](#reporting-bugs)
        - [Before Submitting a Bug Report](#before-submitting-a-bug-report)
        - [How To Submit a Good Bug Report](#how-to-submit-a-good-bug-report)
    + [Suggesting Enhancements](#suggesting-enhancements)
        - [Before Submitting an Enhancement](#before-submitting-an-enhancement)
        - [How Do I Submit a Good Enhancement Suggestion?](#how-do-i-submit-a-good-enhancement-suggestion)


## Code of Conduct

This project and everyone participating in it is governed by the
[CONTRIBUTING.md Code of Conduct](./CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code.


## I Want To Contribute

> ### Legal Notice
> When contributing to this project, you must agree that you have authored 100% of the content, that you have the necessary rights to the content and that the content you contribute will be provided under the project license.


### Setting Up a Developer Environment

#### Prerequisites

* C99-compatible compiler
* Python 3.X+ (where `X` is the minimum supported patch version in [pyproject.toml](./pyproject.toml))
> :bulb: Ideally you should have all versions listed in [.python-version](./.python-version) installed and available in your path. This will ensure your changes work on all supported python versions. An easy way to manage multiple python installations is via [pyenv](https://github.com/pyenv/pyenv).
* `nox` (can be installed via pip)

#### Running the unit tests

```bash
nox -s test # Or nox -s test-3.X to test a specific python version
```

#### Building the wheels and sdist

```bash
nox -s sdist wheel # Or nox -s wheel-3.X to build for a specific python version
```

#### Other Commands

You can see all available commands (sessions) with the following command:

```bash
nox --list
```

### Submitting a Pull Request

1. Fork and clone the repository.
1. Install the [dependencies](#prerequisites).
1. Make sure you can [build](#building-the-wheels-and-sdist) the project and all [tests pass](#running-the-unit-tests) on your machine.
1. Create a new branch: `git checkout -b my-branch-name`.
1. Make your change, add tests, and make sure the tests still pass.
1. Push to your fork and submit a pull request.
1. Pat your self on the back and wait for your pull request to be reviewed and merged.

Work in Progress pull requests are also welcome to get feedback early on, or if there is something blocking you.


#### How To Submit a Good Pull Request

* Format, lint and type check your code.
```bash
nox -s lint format typeCheck
```
* Comment your code.
* Write and update tests.
* Keep your changes as focused as possible. If there are multiple changes you would like to make that are not dependent upon each other, consider submitting them as separate pull requests.
* Write detailed commit messages.


### Reporting Bugs

> You must never report security related issues, vulnerabilities or bugs including sensitive information to the issue tracker, or elsewhere in public. See [SECURITY.md](./SECURITY.md) to learn how to report security vulnerabilities.


#### Before Submitting a Bug Report

A good bug report shouldn't leave others needing to chase you up for more information. Therefore, we ask you to investigate carefully, collect information and describe the issue in detail in your report. Please complete the following steps in advance to help fix any potential bug as fast as possible.

* Make sure that you are using the latest version.
* Determine if your bug is really a bug and not an error on your side e.g. incorrect usage or outdated library version.
* Make sure you have gone trough the [usage examples](./README.md#usage-examples) and [Issues](https://github.com/astro-stan/librsync-py/issues) to see if other users have experienced (and potentially already solved) the issue you are having.
* Also make sure to search the internet (including Stack Overflow) to see if users outside of the GitHub community have discussed the issue.
* Collect information about the bug: callstack, configuration, minimal reproducible example.


#### How To Submit a Good Bug Report

This project uses GitHub issues to track bugs and errors. If you run into an issue with the project:

- Open an [Issue](https://github.com/astro-stan/librsync-py/issues/new).
- Explain the behavior you would expect and the actual behavior.
- Please provide as much context as possible and describe the **reproduction steps** that someone else can follow to recreate the issue on their own. This usually includes your code. For good bug reports you should isolate the problem and create a minimal reproducible test case.

Once it's filed:

- A maintainer will try to reproduce the issue with your provided steps. If there are no reproduction steps or no obvious way to reproduce the issue, the team will ask you for those steps.
- If the maintainer is not able to reproduce the issue, your issue may be closed without a fix. Otherwise, they will work on a fix and release it as soon as possible.


### Suggesting Enhancements

#### Before Submitting an Enhancement

- Make sure that you are using the latest version.
- Check the [usage examples](./README.md#usage-examples) to find out if the functionality is already covered, ideally also check the source code.
- Perform a [search](https://github.com/astro-stan/librsync-py/issues) to see if the enhancement has already been suggested. If it has and you have additional information you feel the maintainers need to know comment on the existing issue. However, please refrain from commenting "+1", "me too" or similar, as it is unnecessary.
- Find out whether your idea fits with the scope and aims of the project. It's up to you to make a strong case to convince the project's maintainers of the merits of this feature. Keep in mind that features should be useful to the majority of users and not just a small subset. If you're just targeting a minority of users, consider forking/writing your own library.


#### How Do I Submit a Good Enhancement Suggestion?

Enhancement suggestions are tracked as [GitHub issues](https://github.com/astro-stan/librsync-py/issues).

- Use a **clear and descriptive title** for the issue to identify the suggestion.
- Provide a **step-by-step description of the suggested enhancement** in as many details as possible.
- **Describe the current behavior** and **explain which behavior you expected to see instead and why**. At this point you can also tell which alternatives do not work for you.
- **Explain why this enhancement would be useful** to most users. You may also want to point out the other projects that solved it better and which could serve as inspiration.
