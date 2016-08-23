# Assorted utilities for devops

* `depdeb.sh` -- script to recursively list package dependencies to any given depth
* `maas-net-config.sh` -- script to check network config of a MAAS Controller node
* `00-aaaa-maas-intra-diag.sh` -- "commissioning script" to perform diagnostics of a node that turns into "Failed commissioning" state
* `maas-rc-local.sh` -- a plug for /etc/rc.local to setup MAAS Controller node
* `certgen.py` -- generate certs for RH OpenStack installer **`undercloud`**
  * When you're digging through the [manual](https://access.redhat.com/documentation/en/red-hat-openstack-platform/8/paged/director-installation-and-usage/appendix-a-ssl-tls-certificate-configuration), you ~~may~~ _will_ face a problem generating suitable certificates and [this small Python code](certgen.py) is your friend.
Take a look at it and edit [settings near the top of the file](certgen.py#L10) to reflect your configuration: even if you aren't changing UnderCloud's defaults, you'll probably state your vision of life in `req_distinguished_name` [section](certgen.py#L34).
* `iflist.py` -- a way to find (1) network interfaces and (2) their respective IP addresses, if any.
