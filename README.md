# Baskio - Build And Scan Kubernetes Images Openstack

A binary for building and scanning (with [Trivy](https://github.com/aquasecurity/trivy)) a Kubernetes image using
the [eschercloud-image-builder](https://github.com/eschercloudai/image-builder) repo.
Once the image has been built, the CVE results will be pushed to GitHub Pages. Simply provide the required GitHub
flags/config file, and it will do the rest for you.

# Scope

⚠️Currently in beta at the moment.

# Prerequisites

### Openstack

It is expected that you have a network and sufficient security groups in place to run this.<br>
It will not create the network or security groups for you.

For example:

```
openstack network create image-builder
openstack subnet create image-builder --network image-builder --dhcp --dns-nameserver 1.1.1.1 --subnet-range 10.10.10.0/24 --allocation-pool start=10.10.10.10,end=10.10.10.200
openstack router create image-builder --external-gateway public1
openstack router add subnet image-builder image-builder

OS_SG=$(openstack security group list -c ID -c Name -f json | jq '.[]|select(.Name == "default") | .ID')
openstack security group rule create "${OS_SG}" --ingress --ethertype IPv4 --protocol TCP --dst-port 22 --remote-ip 0.0.0.0/0 --description "Allows SSH access"
openstack security group rule create "${OS_SG}" --egress --ethertype IPv4 --protocol TCP --dst-port -1 --remote-ip 0.0.0.0/0 --description "Allows TCP Egress"
openstack security group rule create "${OS_SG}" --egress --ethertype IPv4 --protocol UDP --dst-port -1 --remote-ip 0.0.0.0/0 --description "Allows UDP Egress"
```

# Usage
Simply run the binary with the following flags (minimum required). See the example below.
You will also require a source image to reference for the build to succeed.
You must supply a clouds.yaml file for Openstack connectivity.

```yaml
clouds-file: "~/.config/openstack/clouds.yaml"
cloud-name: "image-builder"
build:
  build-os: "ubuntu-2204"
  attach-config-drive: false
  #image-repo: ""
  network-id: "network-id"
  source-image: "source-image"
  flavor-name: "spicy-meatball"
  use-floating-ip: true
  floating-ip-network-name: "Internet"
  image-visibility: "private"
  crictl-version: "1.25.0"
  kubernetes-version: "1.25.3"
  extra-debs: "nfs-common"
  enable-nvidia-support: false
  nvidia-installer-url: "nvidia-install-download-url"
  nvidia-driver-version: "used-for-image-name"
  grid-license-server: "grid-server-ip"
scan:
  image-id: ""
  flavor-name: "spicy-meatball"
  network-id: "network-id"
  attach-config-drive: false
publish: 
  image-id: ""
  github:
    user: "some-user"
    project: "some-project"
    token: "123456789"
    pages-branch: ""
  results-file: ""

```

Now supply this to baskio.
```shell
# Build an image
baskio build --baskio-config path-to-config.yaml

# Scan an image
baskio scan --baskio-config path-to-config.yaml

# Publish the CVEs
baskio publish --baskio-config path-to-config.yaml
```

### More info

For more flags and more info, run `baskio --help`

### GitHub Pages

You will need to set up your target repo for the GitHub Pages in advanced.
It only requires a `gh-pages` branch for this to work.
GitHub Pages should be configured to point to a `docs` directory as this is where the resulting static site will be
placed.

# TODO
* Create all option to allow whole process
* Make scanning a separate binary instead of packaging it in here - started process here by separating out building, scanning & publishing
* Make this work for more than just Openstack so that it's more useful to the community around the Kubernetes Image Builder?

# License

The scripts and documentation in this project are released under the [Apache v2 License](LICENSE).