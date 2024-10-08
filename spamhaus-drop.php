<?php
declare(strict_types=1);

define('myName', 'spamhaus-drop.php');
define('myVersion', '20241004');
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
 */

/*	spamhaus-drop.php
**	***
**  * configuration variables in environment
**  SPAMHAUS_DROP_noIPV4
**  SPAMHAUS_DROP_noIPV6
**  SPAMHAUS_DROP_noTIMEOUT
**  SPAMHAUS_DROP_useCOUNTER
**	* use as script
**	php spamhaus-drop.php --help --prepare --refresh --clear
**	--prepare	prepare netfilter firewall table
**	--clear		clear the netfilter table
**	--flush		flush the named sets
**	--refresh	load new list and apply to netfilter
**	* import as library
**	require_once('spamhaus-drop.php');
**	require('spamhaus-drop.php');
**	include('spamhaus-drop.php');
*/

//	PHP should be >=8.0, <8.4
//	there is no specific need, just did not test others
if (80000 >= PHP_VERSION_ID || 80400 <= PHP_VERSION_ID) {
	http_response_code(500);
	echo 'Your current PHP version ' . PHP_VERSION . ' is unsupported.';
	exit(1);
}

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
	//	configuration
	public $jsonURIs = array(
		'https://www.spamhaus.org/drop/drop_v4.json',
		'https://www.spamhaus.org/drop/drop_v6.json',
		'https://www.spamhaus.org/drop/asndrop.json',
	);
	public $noIPV4 = null;
	public $noIPV6 = null;
	public $noTIMEOUT = null;
	public $useCOUNTER = null;
	//	properties
	protected $lastError = false;		// no error
    protected $dropList = null;			// the actual DROP list loaded from URI
    protected $curlReturn = null;		// the returned file time
    protected $listTimestamp = null;	// the cURL return code
    protected $dropListArray = array();	// the DROP list decoded to array
	protected $lastExecOutput = null;	// output array for exec calls
	protected $lastExecReturn = null;	// return code for exec calls
	//	constructor, destructor
	public function __construct($listURI=null) {
		// get configured
		if(array_key_exists('SPAMHAUS_DROP_noIPV4',$_ENV))
			$this->noIPV4 = ! in_array(array("0","no","NO","false","FALSE"),$_ENV['SPAMHAUS_DROP_noIPV4']);
		else
			$this->noIPV4 = ! $this->haveIPv4();
		if(array_key_exists('SPAMHAUS_DROP_noIPV6',$_ENV))
			$this->noIPV6 = ! in_array(array("0","no","NO","false","FALSE"),$_ENV['SPAMHAUS_DROP_noIPV6']);
		else
			$this->noIPV6 = ! $this->haveIPv6();
		if(array_key_exists('SPAMHAUS_DROP_noTIMEOUT',$_ENV))
			$this->noTIMEOUT = ! in_array(array("0","no","NO","false","FALSE"),$_ENV['SPAMHAUS_DROP_noTIMEOUT']);
		if(array_key_exists('SPAMHAUS_DROP_useCOUNTER',$_ENV))
			$this->useCOUNTER = ! in_array(array("0","no","NO","false","FALSE"),$_ENV['SPAMHAUS_DROP_noTIMEOUT']);
		// load given list
		if($listURI)
			$this->loadJson($listURI);
	}
	public function __destruct() {
	}
	//	methods
	function __exec($command=null, $showError=false) {
        // throw ValueError if no command given
        unset($this->lastExecOutput);	// do not append to output
        unset($this->lastExecReturn);
		$returnCode = exec($command . ($showError ? "" : " 2> /dev/null"), $this->lastExecOutput, $this->lastExecReturn);
		if ($returnCode != 0) {
			// error handling
			$this->lastError = "exec failed (code " . $returnCode . ")";
		}
		return( $returnCode );
	}
	public function deleteRules() {
        // check table does exist
        if ( $this->__exec('nft list table inet spamhaus') ) {
            // delete table
            $this->__exec('nft delete table inet spamhaus');
        }
        // return
		return( ! $this->__exec('nft list table inet spamhaus') );
	}
	public function prepareRules() {
        // check table does not exist
        if ( ! $this->__exec('nft list table inet spamhaus') ) {
            // add table
            $this->__exec('nft add table inet spamhaus');
        }
        // check named set does not exist
        if ( ! $this->__exec('nft list set inet spamhaus drop_ipv4') ) {
            // add named set
            $this->__exec('nft add set inet spamhaus drop_ipv4 \{ type ipv4_addr\; flags interval' . ($this->noTIMEOUT ? '' : ', timeout') . '\; auto-merge\; comment \"SPAMHAUS do not route or peer\"\; \}');
        }
        /*else {
            $this->__exec('nft flush set inet spamhaus drop_ipv4');
        }*/
        // check named set does not exist
        if ( ! $this->__exec('nft list set inet spamhaus drop_ipv6') ) {
            // add named set
            $this->__exec('nft add set inet spamhaus drop_ipv6 \{ type ipv6_addr\; flags interval' . ($this->noTIMEOUT ? '' : ', timeout') . '\; auto-merge\; comment \"SPAMHAUS do not route or peer\"\; \}');
        }
        /*else {
            $this->__exec('nft flush set inet spamhaus drop_ipv6');
        }*/
        // check chain does not exist
        if ( ! $this->__exec('nft list chain inet spamhaus prerouting') ) {
            // add chain
            $this->__exec('nft add chain inet spamhaus prerouting \{ type filter hook prerouting priority -100\; \}');
            // add rules
            $this->__exec('nft add rule inet spamhaus prerouting ip saddr @drop_ipv4 ' . ($this->useCOUNTER ? 'counter' : '') . ' drop');
            $this->__exec('nft add rule inet spamhaus prerouting ip daddr @drop_ipv4 ' . ($this->useCOUNTER ? 'counter' : '') . ' drop');
            $this->__exec('nft add rule inet spamhaus prerouting ip6 saddr @drop_ipv6 ' . ($this->useCOUNTER ? 'counter' : '') . ' drop');
            $this->__exec('nft add rule inet spamhaus prerouting ip6 daddr @drop_ipv6 ' . ($this->useCOUNTER ? 'counter' : '') . ' drop');
        }
        // check chain does not exist
        if ( ! $this->__exec('nft list chain inet spamhaus postrouting') ) {
            // add chain
            $this->__exec('nft add chain inet spamhaus postrouting \{ type filter hook postrouting priority 100\; \}');
            // add rules
            $this->__exec('nft add rule inet spamhaus postrouting ip daddr @drop_ipv4 ' . ($this->useCOUNTER ? 'counter' : '') . ' drop');
            $this->__exec('nft add rule inet spamhaus postrouting ip6 daddr @drop_ipv6 ' . ($this->useCOUNTER ? 'counter' : '') . ' drop');
        }
        // return
        return($this->__exec('nft list chain inet spamhaus prerouting'));
	}
	public function flushSets() {
        // check named set does exist
        if ( $this->__exec('nft list set inet spamhaus drop_ipv4') ) {
            // flush named set
            $this->__exec('nft flush set inet spamhaus drop_ipv4');
        }
        // check named set does exist
        if ( ! $this->__exec('nft list set inet spamhaus drop_ipv6') ) {
            // flush named set
            $this->__exec('nft flush set inet spamhaus drop_ipv6');
        }
        // return
        return($this->__exec('nft list table inet spamhaus'));
	}
	public function addElement2nft($ipaddr=null) {
		list($network, $netmask) = explode('/', $ipaddr, 2);	// split IP address from netmask
		if (filter_var($network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && (! $this->noIPV4))
			$this->__exec('nft add element inet spamhaus drop_ipv4 \{ ' . $ipaddr . ' ' . ($this->noTIMEOUT ? '' : 'timeout 72h') . ' \}');
		elseif (filter_var($network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && (! $this->noIPV6))
			$this->__exec('nft add element inet spamhaus drop_ipv6 \{ ' . $ipaddr . ' ' . ($this->noTIMEOUT ? '' : 'timeout 72h') . ' \}');
		else {
			$this->lastError = "invalid IP " . $ipaddr;
			echo $this->lastError . PHP_EOL;
		}
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
		$this->dropList = curl_exec($curlHandle);	// execute and store response
		$responseCode = curl_getinfo($curlHandle, CURLINFO_RESPONSE_CODE);	// get HTTP status 
		if ($responseCode > $this->curlReturn)
			$this->curlReturn = $responseCode;	// store only if greater than
		$fileTime = curl_getinfo($curlHandle, CURLINFO_FILETIME);	// get file time
		if ($fileTime > $this->listTimestamp)
			$this->listTimestamp = $fileTime;	// store only if greater than
		if ($responseCode != 200) {
				// error handling
				$this->lastError = curl_error($curlHandle);
		}
		elseif ($this->dropList) {
			// process only if response 200/HTTP_OK and not empty
			foreach (explode(PHP_EOL, $this->dropList) as $json)			// take each line from json
				array_push($this->dropListArray, json_decode($json, true));	// append to array
		}
		curl_close($curlHandle);
	}
	public function loadElements() {
		$this->prepareRules();	// always prepare rules before loading elements
		// prepare bind9 response-policy-zone
		$fileRPZ = fopen('/etc/bind/response-policy-zone','c');
		if($fileRPZ) {
			fwrite($fileRPZ,'$ORIGIN response.policy.zone.' . PHP_EOL);
			fwrite($fileRPZ,'/*	examples' . PHP_EOL . PHP_EOL);
			fwrite($fileRPZ,'; destination IP rewrite' . PHP_EOL . 'baddomain1.example.com       A     198.51.100.1' . PHP_EOL . '*.baddomain1.example.com     A     198.51.100.1' . PHP_EOL . PHP_EOL);
			fwrite($fileRPZ,'; send them to an existing A record' . PHP_EOL . 'baddomain2.example.com       CNAME mywebserver.example.org.' . PHP_EOL . '*.baddoman2.example.com      CNAME mywebserver.example.org.' . PHP_EOL . PHP_EOL);
			fwrite($fileRPZ,'; NXDOMAIN it' . PHP_EOL . 'baddomain3.example.com       CNAME .' . PHP_EOL . '*.baddomain3.example.com     CNAME .' . PHP_EOL . PHP_EOL);
			fwrite($fileRPZ,'; reply with NODATA' . PHP_EOL . 'baddomain4.example.com       CNAME *.' . PHP_EOL . '*.baddomain4.example.com     CNAME *.' . PHP_EOL . PHP_EOL);
			fwrite($fileRPZ,'*/' . PHP_EOL . PHP_EOL);
		}
		$fileDROP = fopen('/etc/bind/spamhaus-drop','c');
		if($fileDROP) {
			fwrite($fileDROP,'acl spamhaus-drop {' . PHP_EOL);
		}
		// walk the entries
		foreach ($this->dropListArray as $element) {
			if (is_null($element))	continue;	// skip null elements
			if (array_key_exists("cidr",$element)) {
				$this->addElement2nft($element["cidr"]);
				fwrite($fileDROP,"\t" . $element["cidr"] . ';' . PHP_EOL);
			}
			elseif (array_key_exists("domain",$element)) {
				fwrite($fileRPZ,$element["domain"] . '   CNAME .' . PHP_EOL);
				fwrite($fileRPZ,'*.' . $element["domain"] . ' CNAME .' . PHP_EOL);
				fwrite($fileRPZ,PHP_EOL);
			}
		}
		// close bind files
		fclose($fileRPZ);
		if($fileDROP) {
			fwrite($fileDROP,'};' . PHP_EOL);
			fclose($fileDROP);
		}
	}
	// access method
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
	public function getStatusCode() {
		return($this->curlReturn);
	}
	public function getTimestamp() {
		return($this->listTimestamp);
	}
	public function getLastError() {
		return($this->lastError);
	}
	// helper methods
	public function haveIPv4() {
		return(extension_loaded('sockets') && defined('AF_INET'));
	}
	public function haveIPv6() {
		return(extension_loaded('sockets') && defined('AF_INET6'));
	}
}

//	running from CLI
if ( (PHP_SAPI == "cli" && defined('STDIN')) && $_SERVER['argc'] >= 1 ) {
	// startet with arguments
	$shortOptions = "h" . "p" . "r" . "c" . "f";
	$longOptions = array('help','prepare','refresh','clear','flush');
	$options = getopt($shortOptions,$longOptions);
	// run
	if (count($options) == 0 || array_key_exists("help",$options) || array_key_exists("h",$options)) {
		// help
		echo myName .'/'. myVersion .' '. myComment . PHP_EOL;
		echo '--help, -h', "\t", 'show this help page', PHP_EOL;
		echo '--clear, -c', "\t", 'remove netfilter table', PHP_EOL;
		echo '--prepare, -p', "\t", 'prepare netfilter table', PHP_EOL;
		echo '--flush, -f', "\t", 'flush netfilter sets', PHP_EOL;
		echo '--refresh, -r', "\t", 'refresh DROP', PHP_EOL;
		// error out
		http_response_code(200);
		die("Please run " .__FILE__. " with desired options." .PHP_EOL);
	}
	else {
		$DROP = new spamhaus_DROP();
		if (array_key_exists("refresh",$options) || array_key_exists("r",$options)) {
			$DROP->loadJson();	// load all lists
			if ($DROP->getStatusCode() > 200) {
				// error handling
				http_response_code($DROP->getStatusCode());
				die($DROP->getLastError() . PHP_EOL);
			}
		}
		if (array_key_exists("clear",$options) || array_key_exists("c",$options)) {
			$DROP->deleteRules();	// will remove netfilter table
		}
		if (array_key_exists("prepare",$options) || array_key_exists("p",$options)) {
			$DROP->prepareRules();
		}
		if (array_key_exists("flush",$options) || array_key_exists("f",$options)) {
			$DROP->flushSets();
		}
		if (array_key_exists("refresh",$options) || array_key_exists("r",$options)) {
			$DROP->loadElements();	// will always prepare rules and/or flush sets
		}
	}
}
//	check running directly, without being included
elseif ( $_SERVER['PHP_SELF'] == __FILE__ ) {
	http_response_code(500);
	die("Please do not run " .__FILE__. " directly." .PHP_EOL);
}

// end PHP script
?>
