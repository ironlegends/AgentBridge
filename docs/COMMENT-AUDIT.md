# Rust Comment Audit - 2026-11-22

## Scope and result

The automated inventory covers all tracked and non-ignored Rust source files in the working tree, including the CLI, workspace crates, native desktop application and new Unix adapters. It does not claim to semantically review every comment or to lint JavaScript, HTML, Python, shell scripts or prose.

At the `9406613` native-candidate checkpoint, the inventory reports:

| Measure | Count |
| --- | ---: |
| Rust source files | 111 |
| Comment tokens | 2,790 |
| Documentation comment tokens | 1,299 |
| Other comment tokens | 1,491 |
| Deferred-work markers or purely decorative dividers | 0 |

A token can span multiple lines. These counts are not physical comment-line counts. The complete JSON inventory was generated locally with `--report`; the command below reproduces it from any checkout. Future source edits may change the counts while leaving the debt budget at zero.

## Review decisions

Focused manual review covered comments explaining live-profile lock admission, synchronous process revocation, immutable OAuth authority, Windows Job/Unix process-group ownership, workspace-handle transfer, native Chrome profile cleanup, window identity and native FFI boundaries.

Those comments preserve information the syntax alone does not establish: why a lock remains held through an effect, why a process leader is retained before group cleanup, why path witnesses cannot replace directory capabilities, and why a platform operation must fail closed. They were retained.

License/SPDX notices, public API documentation, safety rationales and tooling directives remain protected. No broad comment-deletion pass was performed, and no boilerplate-removal count is presented as a quality metric. Empty findings for the two automated rules do not prove that every ordinary comment is necessary or current.

## Ratchet policy

`scripts/rust/comment_ratchet.py` recognizes Rust comments while skipping ordinary/raw/byte/C string literals and character literals, and handles nested block comments. It reports:

- Deferred-work markers: `TODO`, `FIXME`, `HACK` and `XXX`.
- Comments consisting only of a decorative divider.

Existing debt is represented by file, rule, normalized-comment fingerprint and occurrence count. Moving an unchanged allowed comment within its file preserves its identity. Rewording it, moving it to a different file or duplicating it creates a new finding. Removing one finding does not fund a different comment.

The current baseline contains zero findings. CI compares with the pull request's base commit, or the prior main-branch commit for a push. It reads the base source directly from Git; editing the baseline file cannot grant permission to add debt. The complete PR comparison also prevents a later clean commit from hiding debt introduced by an earlier commit.

Four focused tests verify lexical handling, protected documentation/safety content, fingerprint stability and multiplicity. The current fixture suite passes.

## Commands

```sh
python3 -m unittest discover -s scripts/rust -p test_comment_ratchet.py
python3 scripts/rust/comment_ratchet.py
python3 scripts/rust/comment_ratchet.py --base-ref <reviewed-base-commit>
python3 scripts/rust/comment_ratchet.py --report <new-report-path.json>
```

A change in the debt policy or an exceptional baseline update must be reviewed as a policy change. It is not a way to hide new findings from the CI comparison.

## Personal cleanup workflow

The requested personal `/delete-comment` skill is installed separately from the repository runtime. It scopes cleanup to the requested files or active diff, removes only demonstrably redundant or obsolete comments, preserves literals/token boundaries and protects contracts, safety explanations, licenses and tooling directives.

Baseline and skill-assisted fixture applications both retained protected comments and removed only redundant narration. Metadata validation passed. This is a verified positive-use workflow, not a claim that the baseline agent failed. The skill has no runtime authority to modify unrelated files or silently change executable behavior.
