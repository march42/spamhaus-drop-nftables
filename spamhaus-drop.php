<?php
declare(strict_types=1);

define('myName', 'spamhaus-drop.php');
define('myVersion', '20241001');
define('myComment', 'load spamhaus DROP to netfilter set, see https://github.com/march42/spamhaus-drop-nftables');

/**
 * @copyright Copyright (c) 2024 Marc Hefter <marchefter@march42.net>
 *
 * @author Marc Hefter <marchefter@march42.net>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

/*	spamhaus-drop.php
**	Version 20240930
**	(C) Copyright 2024 by Marc Hefter <marchefter@march42.net>
**	***
**	* import as library
**	require_once('spamhaus-drop.php');
**	require('spamhaus-drop.php');
**	include('spamhaus-drop.php');
**	* use as script
**	php spamhaus-drop.php --help --prepare --refresh --clear
**	--prepare	prepare netfilter firewall table
**	--refresh	load new list and apply to netfilter
**	--clear		clear the netfilter table
**  * configuration variables in environment
**  SPAMHAUS_DROP_noIPV4
**  SPAMHAUS_DROP_noIPV6
**  SPAMHAUS_DROP_useTIMEOUT
**  SPAMHAUS_DROP_useCOUNTER
**  if variable set in environment
*/

//	PHP should be >=8.0, <8.4
if (80000 >= PHP_VERSION_ID || 80400 <= PHP_VERSION_ID) {
	http_response_code(500);
	echo 'Your current PHP version ' . PHP_VERSION . ' is unsupported.';
	exit(1);
}

//	IPv4	extension_loaded('sockets') && defined('AF_INET')
//	IPv6	extension_loaded('sockets') && defined('AF_INET6')

class spamhaus_DROP
{
	/*	DROP list class
	**	***
	**	load from spamhaus.org
	**	https://www.spamhaus.org/drop/drop_v4.json
	**		{"cidr":"223.254.0.0/16","sblid":"SBL212803","rir":"apnic"}
	**		{"type":"metadata","timestamp":1727634153,"size":82682,"records":1354,"copyright":"(c) 2024 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}
	**	https://www.spamhaus.org/drop/drop_v6.json
	**		{"cidr":"2a14:7c3::/32","sblid":"SBL641930","rir":"ripencc"}
	**		{"type":"metadata","timestamp":1727436153,"size":4926,"records":78,"copyright":"(c) 2024 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}
	**	https://www.spamhaus.org/drop/asndrop.json
	**		{"asn":400992,"rir":"arin","domain":"62yun.com","cc":"RU","asname":"ZHOUYISAT-COMMUNICATIONS"}
	**		{"type":"metadata","timestamp":1727686353,"size":24956,"records":280,"copyright":"(c) 2024 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}
	**	***
	**	identify list
	**	get array of ip ranges
	*/
	//	properties
	public $jsonURIs = array(
		'https://www.spamhaus.org/drop/drop_v4.json',
		'https://www.spamhaus.org/drop/drop_v6.json',
		#'https://www.spamhaus.org/drop/asndrop.json',
	);
    protected $dropList = null;			// the actual DROP list loaded from URI
    protected $curlReturn = null;		// the returned file time
    protected $listTimestamp = null;	// the cURL return code
    protected $dropListArray = array();	// the DROP list decoded to array
	protected $lastExecOutput = null;	// output array for exec calls
	protected $lastExecReturn = null;	// return code for exec calls
	//	constructor, destructor
	/*	constructor
	**	***
	**	$elementTimeout=-1	-1 is no timeout, else string 3d or 72h
	**	$resetRules=false	delete and reprepare rules
	**	$cachePath=null		filepath, to cache lists
	*/
	public function __construct($elementTimeout=-1, $resetRules=false, $cachePath=null) {
	}
	public function __destruct() {
	}
	//	methods
	function __exec($command=null) {
        // throw ValueError if no command given
        unset($this->lastExecOutput);
        unset($this->lastExecReturn);
		return( exec( $command, $this->lastExecOutput, $this->lastExecReturn ) );
	}
	public function deleteRules() {
        // check table does exist
        if ( $this->__exec('nft list table inet spamhaus 2> /dev/null') ) {
            // delete table
            $this->__exec('nft delete table inet spamhaus');
        }
        // return
		return( ! $this->__exec('nft list table inet spamhaus') );
	}
	public function prepareRules() {
        // check table does not exist
        if ( ! $this->__exec('nft list table inet spamhaus 2> /dev/null') ) {
            // add table
            $this->__exec('nft add table inet spamhaus');
        }
        // check named set does not exist
        if ( ! $this->__exec('nft list set inet spamhaus drop_ipv4 2> /dev/null') ) {
            // add named set
            $this->__exec('nft add set inet spamhaus drop_ipv4 \{ type ipv4_addr\; flags interval, timeout\; auto-merge\; comment \"SPAMHAUS do not route or peer\"\; \}');
        }
        /*else {
            $this->__exec('nft flush set inet spamhaus drop_ipv4');
        }*/
        // check named set does not exist
        if ( ! $this->__exec('nft list set inet spamhaus drop_ipv6 2> /dev/null') ) {
            // add named set
            $this->__exec('nft add set inet spamhaus drop_ipv6 \{ type ipv6_addr\; flags interval, timeout\; auto-merge\; comment \"SPAMHAUS do not route or peer\"\; \}');
        }
        /*else {
            $this->__exec('nft flush set inet spamhaus drop_ipv6');
        }*/
        // check chain does not exist
        if ( ! $this->__exec('nft list chain inet spamhaus prerouting 2> /dev/null') ) {
            // add chain
            $this->__exec('nft add chain inet spamhaus prerouting \{ type filter hook prerouting priority -100\; \}');
            // add rules
            $this->__exec('nft add rule inet spamhaus prerouting ip saddr @drop_ipv4 counter drop');
            $this->__exec('nft add rule inet spamhaus prerouting ip daddr @drop_ipv4 counter drop');
            $this->__exec('nft add rule inet spamhaus prerouting ip6 saddr @drop_ipv6 counter drop');
            $this->__exec('nft add rule inet spamhaus prerouting ip6 daddr @drop_ipv6 counter drop');
        }
        // check chain does not exist
        if ( ! $this->__exec('nft list chain inet spamhaus postrouting 2> /dev/null') ) {
            // add chain
            $this->__exec('nft add chain inet spamhaus postrouting \{ type filter hook postrouting priority 100\; \}');
            // add rules
            $this->__exec('nft add rule inet spamhaus postrouting ip daddr @drop_ipv4 counter drop');
            $this->__exec('nft add rule inet spamhaus postrouting ip6 daddr @drop_ipv6 counter drop');
        }
        // return
        return($this->__exec('nft list chain inet spamhaus prerouting 2> /dev/null'));
	}
	public function flushSets() {
        // check named set does exist
        if ( $this->__exec('nft list set inet spamhaus drop_ipv4 2> /dev/null') ) {
            // flush named set
            $this->__exec('nft flush set inet spamhaus drop_ipv4');
        }
        // check named set does exist
        if ( ! $this->__exec('nft list set inet spamhaus drop_ipv6 2> /dev/null') ) {
            // flush named set
            $this->__exec('nft flush set inet spamhaus drop_ipv6');
        }
        // return
        return($this->__exec('nft list table inet spamhaus 2> /dev/null'));
	}
	public function addElement($ipaddr=null) {
		list($network, $netmask) = explode('/', $ipaddr, 2);	// split IP address from netmask
		if (filter_var($network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))
			$this->__exec('nft add element inet spamhaus drop_ipv4 \{ ' . $ipaddr . ' timeout 72h \} 2> /dev/null');
		elseif (filter_var($network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
			$this->__exec('nft add element inet spamhaus drop_ipv6 \{ ' . $ipaddr . ' timeout 72h \} 2> /dev/null');
		else
			echo "invalid IP " . $ipaddr . PHP_EOL;
        // return
	}
	public function loadJson($URI=null) {
		if (empty($URI)) {
			foreach ($this->jsonURIs as $uri) {
				$this->loadJson($uri);
			}
			return(false);
		}
		// load JSON list
		$curlHandle = curl_init();
		$curlOptions = array(
			CURLOPT_USERAGENT => myName .'/'. myVersion .' '. myComment,	// HTTP UserAgent
			CURLOPT_URL => $URI,						// URI to retreive
			CURLOPT_HTTPGET => true,					// use HTTP GET method
			CURLOPT_RETURNTRANSFER => true,				// return response as string
			CURLOPT_HEADER => false,					// do not add response headers to output
			CURLOPT_AUTOREFERER => true,				// set Referer on redirects
			CURLOPT_DISALLOW_USERNAME_IN_URL => true,	// do not allow username and password in URI
			CURLOPT_DNS_SHUFFLE_ADDRESSES => true,		// shuffle the addresses returned
			CURLOPT_FILETIME => true,					// curl_getinfo($curlHandle,CURLINFO_FILETIME)
			CURLOPT_FOLLOWLOCATION => true,				// follow Location: response header
			CURLOPT_HTTPAUTH => CURLAUTH_ANYSAFE,		// allow only safe authentication methods
			CURLOPT_PROTOCOLS => CURLPROTO_HTTP|CURLPROTO_HTTPS|CURLPROTO_FILE,	// allowed protocols, especially for redirects
			#CURLOPT_USERPWD => "[username]:[password]",
			#CURLOPT_FILE => CACHEFILE,	// file that the transfer should be written to
		);
		curl_setopt_array($curlHandle, $curlOptions);
		$this->dropList = curl_exec($curlHandle);	// execute
		$this->curlReturn = curl_getinfo($curlHandle, CURLINFO_RESPONSE_CODE);	// get HTTP status response
		$this->listTimestamp = curl_getinfo($curlHandle, CURLINFO_FILETIME);	// get file time
		if ($this->dropList) {
			foreach (explode(PHP_EOL, $this->dropList) as $json)			// take each line from json
				array_push($this->dropListArray, json_decode($json, true));	// append to array
		}
		curl_close($curlHandle);
	}
	public function loadElements() {
		foreach ($this->dropListArray as $element) {
			if (is_null($element))	continue;
			if (array_key_exists("cidr",$element)) {
				$this->addElement($element["cidr"]);
			}
		}
	}
	// some check methods
	public function getCount() {
		return(count($this->dropListArray));
	}
	public function getArray() {
		return($this->dropListArray);
	}
	public function getReturn() {
		return($this->lastExecReturn);
	}
	public function getOutput() {
		return($this->lastExecOutput);
	}
}


//	running from CLI without arguments given
if ( (PHP_SAPI == "cli" && defined('STDIN')) && $_SERVER['argc'] == 1 ) {
	$DROP = new spamhaus_DROP();
	$DROP->prepareRules();
	$DROP->loadJson();
	$DROP->loadElements();
}
//	running from CLI and arguments given
elseif ( (PHP_SAPI == "cli" && defined('STDIN')) && $_SERVER['argc'] > 1 ) {
	// startet with arguments
	// error out
	http_response_code(418);	// 418 I'm a teapot (RFC 2324, RFC 7168)
	die("Not yet ready " .__FILE__. "" .PHP_EOL);
}
//	check running directly, without being included
elseif ( $_SERVER['PHP_SELF'] == __FILE__ ) {
	http_response_code(500);
	die("Please do not run " .__FILE__. " directly." .PHP_EOL);
}

// end PHP script
?>
