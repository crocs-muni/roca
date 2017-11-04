# Contributing guide

We are very happy to see an interest of the community in improving our detection for ROCA.
We do appreciate it and thank you all! Issues and pull requests are welcome!

With the rising number of feature requests and pull requests we need to set some basic rules to make repository
tidy and working because we have only limited resources for managing this.

## Language ports

In order to make development sustainable and ROCA tool working we would like to separate language ports to different repositories.

Its in general better to have a separate project in the separate GIT repository. Moreover we cannot support large number
of programming languages due to lack of resources and expertise.

So if you created a new ROCA port we would be very happy to link it in our readme in `Language ports` section.
Then please create a PR with the readme update.

Please provide also test vectors.

Thanks!

## Advanced features in python library

We decided the original `detect.py` should do the basic stuff on the basic set of file formats.
We don't wont to overcomplicate this detection tool by adding a lot of different command line switches and parameters.

If you have some advanced feature implemented to it pls in a separate python file inside `roca` package.
For the basic detection please import functions from `detect.py`.

You can register your own tool in the `setup.py` so it has own command name, e.g., `roca-detect-censys` or
`roca-detect-tls`.

Please implement also tests for the new functionality.

