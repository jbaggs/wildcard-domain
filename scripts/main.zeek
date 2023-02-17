##! Add WILDCARD_DOMAIN type to the Intel Framework
##!
##! Whereas DOMAIN is an exact string match, 
##! a WILDCARD_DOMAIN indicator matches as the base domain.
##! (e.g.: "example.com" would match "example.com", "foo.example.com", "foo.bar.example.com", etc.)
##!
##! WILDCARD_DOMAIN matches in the same contexts as the DOMAIN type.
##!
##! Author: Jeremy Baggs

module Intel;

export {
	redef enum Intel::Type += { WILDCARD_DOMAIN, }; 
}

module WildcardDomainIntel;

export {
	const domains: set[string] &redef;
}

module Intel;

event remove_indicator(item: Intel::Item)
	{
	if (item$indicator_type == Intel::WILDCARD_DOMAIN)
		{
		# All intelligence is case insensitive at the moment.
		local lower_indicator = to_lower(item$indicator);
		delete WildcardDomainIntel::domains[lower_indicator];
		}
	}

event new_item(item: Intel::Item)
	{
	if (item$indicator_type == Intel::WILDCARD_DOMAIN)
		{
		# All intelligence is case insensitive at the moment.
		local lower_indicator = to_lower(item$indicator);
		add WildcardDomainIntel::domains[lower_indicator];
		}
	
	}

module WildcardDomainIntel;

function check_wildcard_domain(indicator: string):  PatternMatchResult
	{
	local lower_indicator = to_lower(indicator);
	local p = set_to_regex(domains, "\\.?(~~)$");
	local seen = match_pattern(lower_indicator, p);
	if ( seen$matched ) 
		{
		if ( starts_with(seen$str, ".") )
			seen$str = sub(seen$str, /\./, "");

		else if ( lower_indicator != seen$str )
			{
			seen$matched = F;
			seen$str = "";
			}
		}
	return seen;
	}

event ssl_extension_server_name(c: connection, is_orig: bool, names: string_vec)
	{
	if ( |domains| == 0 )
		return;
	if ( is_orig && c?$ssl && c$ssl?$server_name )
		{
		local seen = check_wildcard_domain(c$ssl$server_name);
		if ( seen$matched )
			Intel::seen([$indicator=seen$str,
				$indicator_type=Intel::WILDCARD_DOMAIN,
				$conn=c,
				$where=SSL::IN_SERVER_NAME]);
		}
        }

event ssl_established(c: connection)
	{
	if ( |domains| == 0 )
		return;
	if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 ||
		! c$ssl$cert_chain[0]?$x509 )
		return;

	if (  c$ssl$cert_chain[0]$x509?$certificate && c$ssl$cert_chain[0]$x509$certificate?$cn )
		{
		local seen = check_wildcard_domain(c$ssl$cert_chain[0]$x509$certificate$cn);
		if ( seen$matched )
			Intel::seen([$indicator=seen$str,
				$indicator_type=Intel::WILDCARD_DOMAIN,
				$fuid=c$ssl$cert_chain[0]$fuid,
				$conn=c,
				$where=X509::IN_CERT]);
		}
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	if ( |domains| == 0 )
		return;
	local seen = check_wildcard_domain(query);
	if ( seen$matched )
		Intel::seen([$indicator=seen$str,
			$indicator_type=Intel::WILDCARD_DOMAIN,
			$conn=c,
			$where=DNS::IN_REQUEST]);
	}

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( |domains| == 0 )
		return;
	if ( is_orig && name == "HOST" )
		{
		# Remove the occasional port value that shows up here.
		local host = gsub(value, /:[[:digit:]]+$/, "");
		if ( ! is_valid_ip(host) )
			{
			local seen =  check_wildcard_domain(host);
			if ( seen$matched )
				{
				Intel::seen([$indicator=seen$str,
					$indicator_type=Intel::WILDCARD_DOMAIN,
					$conn=c,
					$where=HTTP::IN_HOST_HEADER]);
				}
			}
		}
	}

event x509_ext_subject_alternative_name(f: fa_file, ext: X509::SubjectAlternativeName)
	{
	if ( |domains| == 0 )
		return;
	if ( Intel::enable_x509_ext_subject_alternative_name && ext?$dns )
		{
		for ( i in ext$dns )
			{
			local seen = check_wildcard_domain(ext$dns[i]);
			if ( seen$matched )
				Intel::seen([$indicator=seen$str,
					$indicator_type=Intel::WILDCARD_DOMAIN,
					$f=f,
					$where=X509::IN_CERT]);
			}
		}
	}

