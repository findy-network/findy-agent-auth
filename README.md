# findy-template-go

Template structure for Findy Golang projects

## Create new project

1. [Open create new repository view](https://github.com/new).
2. Choose `findy-network/findy-template-go` as the repository template.
3. Clone the newly created repository to local.
4. Create `dev` branch for the new repository:

```
git checkout -b dev
git push --set-upstream origin dev
```

5. Replace ´findy-template-go´ with your project name in relevant source files.
6. Edit this README file and set up the CI tests based on your project.

## Set up CI

Whenever project has private dependencies, personal github token needs to be provided to the go build system.
Add a secret for the project that contains this `HTTPS_PREFIX` setting. This can be done in project settings.

`<HTTPS_PREFIX>` is in the form `<github-username>:<github-token>@` e.g. `lauravuo-techlab:xxx@`

The default CI configuration runs unit tests and linting for each push. Customize the scripts depending on project needs.

For linting in local desktop, you need to install [golangci-lint](https://golangci-lint.run/usage/install/#local-installation)


## Publishing new version

Release script will tag the current version and push the tag to remote. This will trigger e2e-tests in CI automatically and if they succeed, the tag is merged to master.

Release script assumes it is triggered from dev branch. It takes one parameter, the next working version. E.g. if current working version is 0.1.0, following will release version 0.1.0 and update working version to 0.2.0.

```bash
git checkout dev 
./release 0.2.0
```

Implement e2e test to release workflow according to your project needs.

## Makefile 

Makefile in project root contains handy shortcuts for different testing and building related commands.

## Docker image

Dockerfile contains the basic steps for building a simple container with the project executable. Edit or remove according to your project needs.
