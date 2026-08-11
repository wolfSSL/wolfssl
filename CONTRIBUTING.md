# Contributing

Thank you for your interest in contributing. This guide is shared across the wolfSSL Inc. repositories (wolfSSL, wolfSSH, wolfTPM, wolfBoot, wolfMQTT, wolfCLU, wolfPKCS11, wolfHSM, wolfProvider, wolfSentry, and the rest), so it covers what is common to all of them rather than anything specific to this one. Please read the "Contributor Agreement" section below - it is the one requirement that surprises people, and we would rather you know about it up front.

## Ways to Contribute

Pick whichever fits you best. All three are welcome:

1. **Open a pull request.** This is the preferred route and the easiest for us to review, test, and give you credit for.
2. **Email the patch to support@wolfssl.com.** If you would rather not work through GitHub, send us the diff directly and we will take it from there.
3. **File an issue.** Report a defect, ask a question, or propose a change. Use an issue template if the repository offers one. Tell us what the problem is, how to reproduce it, and what you expected instead, and we can take it from there. You do not need to set labels - a maintainer applies those during triage. This is also the route to use if you are unable to submit code at all (see "If You Cannot Sign the Contributor Agreement" below).

## Contributor Agreement (Required)

wolfSSL Inc. dual licenses its software: an open source license - GPLv3 for most projects, see that repository's `LICENSING`, `COPYING`, or `LICENSE` file - and a commercial license for everyone else. To be able to ship your contribution under both, we need to hold the rights to relicense it. That means **we cannot merge a contribution until a signed contributor agreement is on file** for you (and, where applicable, your employer).

**You can open your pull request first and in parallel**:

1. Email **support@wolfssl.com** and ask for the contributor agreement.
2. Include a **reference to your pull request** - a link or the PR number - so we can tie the agreement to the contribution. If you are not going through GitHub, attach the patch you would like to submit instead.
3. Include your **location** (country, and state or region), and **details about your project and how you are using the library**.
4. We will send you the agreement to review and sign.

The review and the agreement proceed independently, so starting both at once is the fastest path to a merge. The signed agreement needs to be on file before we can merge.

The agreement is a short document that grants wolfSSL Inc. a copyright and patent license to your contribution; you otherwise keep all right, title, and interest in your own work, and anything we make available under any license also stays available under an FSF- or OSI-approved open source license. You sign either as an individual or on behalf of your employer, and we send you the full text to read before anything is signed.

The agreement covers all contributions, not just code - documentation changes and one-line typo fixes need one too. There is no size threshold below which it is waived.

## If You Cannot Sign the Contributor Agreement

Some employers do not permit signing third-party agreements, and we understand that. You can still get the change in:

- Open a GitHub issue in the affected repository.
- Describe the problem, how to reproduce it, and the change you believe is correct - in prose, at whatever level of detail you can share.
- We can then implement and test the change ourselves.

If you go this route, please do **not** attach or paste code that you want kept out of the agreement. A clear description of the defect and the intended behavior is enough for us to work from, and it keeps the provenance of the fix unambiguous.

## Before You Start

- **Check the default branch first.** The fix may already be in, or the surrounding code may have moved. Please base your work on the current default branch - `master` in most wolfSSL repositories, `main` in a few.
- **Open an issue for anything large.** New features, API changes, new hardware ports, and behavior changes are much easier to land if we agree on the approach before the code is written.
- **Know the target.** Most wolfSSL projects are portable C (C90 / ANSI C) and run on everything from bare-metal microcontrollers and RTOSes to desktops and servers. Changes that are fine on a modern Linux host can break a build with no filesystem, no heap, no threads, or a different word size. Portability constraints are real and are the most common reason a change needs rework.
- **Build and test details** for each project live in that repository's `README` and `INSTALL` files. This guide deliberately does not duplicate them.

## Submitting a Pull Request

1. Fork the repository and create a topic branch off the default branch.
2. Keep commits focused; one logical change per commit, with a clear message.
3. Open the pull request against that same default branch.
4. Fill out the pull request template if the repository has one - especially the description of what changed and how you tested it.
5. Make sure CI is green - see "Continuous Integration" below.
6. Expect review comments. Most contributions go through at least one round.

## Continuous Integration

Pull requests are checked by two separate systems, and they differ in what you can see.

- **GitHub Actions jobs are public.** Open the "Checks" tab on your pull request, click into any failing job, and read the full log yourself. Please do this first - most failures are a build break or a test regression from the change itself, and you can usually reproduce them locally.
- **Jenkins jobs are internal.** They cover hardware, toolchains, and configurations we cannot expose publicly, so the logs are not visible to you. **If a Jenkins job fails on your pull request, a maintainer will post the relevant errors into the pull request** so you can act on them. If a Jenkins check is red and nobody has commented yet, just ask - it is not something you can debug on your own, and we are happy to paste the output.

The first time you open a pull request, `wolfSSL-Bot` will post "Can one of the admins verify this patch?". That is normal and not a rejection - it just means a maintainer has to approve running CI on code from a new contributor.

CI is broad and occasionally flaky. If a failure looks unrelated to your change, say so in a comment and we will re-run the job.

## What We Look For

- **Match the surrounding style.** Indentation, brace placement, and naming should look like the file you are editing.
- **C90 declarations.** Declare variables at the top of a function or block, not mid-block. No `for (int i = 0; ...)`.
- **`/* ... */` comments only.** No `//` comments in C sources.
- **Avoid `goto`.** We discourage it in new code. Some existing cleanup paths use it, but prefer a single exit point with a return-code variable over adding more.
- **Check every return code.** Do not ignore an error return, and do not add always-succeeds stubs - return a "not implemented" error instead.
- **Free what you allocate,** on every return path.
- **Tests.** Behavior changes and bug fixes should come with a test that fails before the change and passes after.
- **No new compiler warnings.**
- **Keep lines to 80 columns.** This is a hard limit for C sources, headers, and scripts in most wolfSSL repositories, and is checked in CI. It does not apply to Markdown or other documentation - existing wolfSSL docs are not hard-wrapped.
- **Clean source text.** 7-bit ASCII only, no trailing whitespace, and a newline at end of file. Several repositories enforce this in CI.
- **Keep the diff to the point.** Unrelated reformatting makes review harder and is usually asked to be removed.

## Licensing of Contributions

Contributions are accepted under the license of the project you are contributing to - GPLv3 for most wolfSSL repositories, with per-project exceptions in a few. See that repository's `LICENSING`, `COPYING`, or `LICENSE` file for the specifics, including any exceptions. The contributor agreement is what additionally allows wolfSSL Inc. to offer your contribution under a commercial license.

Please only submit code that you have the right to contribute. Do not paste in code taken from another project unless you are certain the license is compatible and you say so in the pull request.

## Reporting Security Issues

**Do not open a public issue or pull request for a security vulnerability.**

Email **support@wolfssl.com** instead, and please keep the issue private until a fix has been released. See `SECURITY.md` in the repository if it has one, or the published policy at
<https://www.wolfssl.com/.well-known/vulnerability-disclosure-policy.txt>.

## Getting Help

- **Support and licensing questions:** support@wolfssl.com
- **Bugs and feature requests:** GitHub issues on the relevant repository
- **Documentation:** <https://www.wolfssl.com/documentation/>
- **Community:** <https://www.wolfssl.com/forums/>
