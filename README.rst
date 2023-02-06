wildcard-domain
===============

In the default configuration, the `Zeek Intelligence Framework <https://docs.zeek.org/en/current/frameworks/intel.html>`_ requires exact matches for detection of intel items.
This script adds a new Intel::WILDCARD_DOMAIN type that matches on the base domain name, regardless of what subdomain may be prepended to it. 
( e.g.: "example.com" would match "example.com", "foo.example.com", "foo.bar.example.com", etc. )

