# DL_Team14_Eric

Course project workspace with local solver iterations, datasets, documents, and
external reference repositories.

## Clone

Clone the repository and all registered reference repositories in one step:

```bash
git clone --recurse-submodules https://github.com/eric-mjk/DL_Team14_Eric.git
```

If you already cloned the repository without submodules, initialize them with:

```bash
git submodule update --init --recursive
```

After pulling new changes, refresh submodules to the commits recorded by the
main repository:

```bash
git pull
git submodule update --init --recursive
```

## Reference Repositories

External references are tracked as Git submodules under `reference_git_repos/`.
The main repository stores only the selected commit for each reference project.

- `reference_git_repos/go-tcg-storage`: https://github.com/open-source-firmware/go-tcg-storage.git
- `reference_git_repos/opal-test-suite`: https://github.com/crocs-muni/opal-test-suite.git
- `reference_git_repos/opal-toolset`: https://github.com/crocs-muni/opal-toolset.git
- `reference_git_repos/sedutil-TCG-OPAL-standard`: https://github.com/0xbadcoffe/sedutil-TCG-OPAL-standard.git

To update a reference repository to a newer upstream commit:

```bash
cd reference_git_repos/<submodule-name>
git fetch
git checkout <commit-or-branch>
cd ../..
git add .gitmodules reference_git_repos/<submodule-name>
git commit -m "Update reference submodule"
```

## Shared Documents

The extracted Core and Opal document text lives once at `documents/`. Each
version folder exposes the same files through `artifacts/documents`, which is a
relative symlink to the shared directory:

```text
<version>/artifacts/documents -> ../../documents
```
