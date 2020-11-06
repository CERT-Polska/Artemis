# k8s setup for artemis

This folder contains k8s configuration files for deploying artemis.

You are required to create on your own:
 - namespace named `artemis`
 - PVC named `artemis`
 - create `karton` secret with `karton.ini` [config file](https://karton-core.readthedocs.io/en/latest/getting_started.html#configuration)
 - change all instances of `<changeme>` in these yaml files
