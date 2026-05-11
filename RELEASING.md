# Releasing Veridion

Veridion releases should be cut from `main`, not `develop`.

## Release discipline

- `develop` is the working branch.
- `main` is the public stable branch.
- tags should be created only from `main`.
- the version in `pyproject.toml` and `src/veridion/__init__.py` must match.

## First official release

The current release target is:

- `v0.1.0`

Before cutting it:

1. Merge the current `develop -> main` PR.
2. Confirm Netlify is deploying from `main`.
3. Confirm the public docs paths on `getveridion.com/docs/` are working.

## Release workflow

There are two supported paths.

### Option 1: GitHub Actions manual release

Run the `Release` workflow from GitHub Actions with:

- `version`: `0.1.0`
- `ref`: `main`

The workflow will:

1. validate version metadata
2. run the test suite
3. create and push the `v0.1.0` tag
4. build the Python distribution
5. create a GitHub release with attached artifacts

### Option 2: Tag push

If you already created a tag from `main`, push it:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The same release workflow will build artifacts and create the GitHub release on tag push.

## After release

After `v0.1.0` exists:

- prefer `uses: veridionhq/veridion@v0.1.0` in external workflows
- prefer `git+https://github.com/veridionhq/veridion.git@v0.1.0` for documented install examples
- continue feature work on `develop`

