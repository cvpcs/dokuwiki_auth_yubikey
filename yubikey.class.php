<?php
/**
 * Yubikey authentication backend
 *
 * Extends plain authentication to allow yubikey password auth
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 */

define('DOKU_AUTH', dirname(__FILE__));
require_once(DOKU_AUTH.'/plain.class.php');

define('AUTH_YUBIKEY_FILE',DOKU_CONF.'yubikey.auth.php');
define('AUTH_YUBIKEY_API_ID', -1);

class auth_yubikey extends auth_plain {

    var $yubikeys = null;

    function auth_yubikey() {
      // just call plain to set up our stuff
      parent::auth_plain();

      // need an api key or we fail
      if (AUTH_YUBIKEY_API_ID < 0){
        $this->success = false;
      }
    }

    /**
     * Check user+password [required auth function]
     *
     * Checks if the given user exists and the given
     * yubikey OTP is correct.  If not, falls back to
     * plain auth.
     *
     * @return  bool
     */
    function checkPass($user,$otp){

      $valid = false;

      // we need a valid user, or fail
      $userinfo = $this->getUserData($user);
      if ($userinfo === false) return false;

      // check if we have a yubikey list to check
      $yubiinfo = $this->getYubiData($user);
      if ($yubiinfo !== false){
        $yubikey = new Yubikey(AUTH_YUBIKEY_API_ID);
        $id = $yubikey->getid($otp);

        // make sure the key we're using is assigned to this user
        if (in_array($id, $yubiinfo))
        {
          // attempt a verification
          $valid = $yubikey->verify($otp);
        }
      }

      // if still not valid, fallback to plain auth
      if (!$valid) {
        $valid = parent::checkPass($user,$otp);
      }

      return $valid;
    }


    /**
     * Return yubikey info
     *
     * Returns info about the given user's yubikeys
     */
    function getYubiData($user){

      if($this->yubikeys === null) $this->_loadYubiData();
      return isset($this->yubikeys[$user]) ? $this->yubikeys[$user] : false;
    }

    /**
     * Load all yubikey data
     *
     * loads the yubikey file into a datastructure
     */
    function _loadYubiData(){
      $this->yubikeys = array();

      if(!@file_exists(AUTH_YUBIKEY_FILE)) return;

      $lines = file(AUTH_YUBIKEY_FILE);
      foreach($lines as $line){
        $line = preg_replace('/#.*$/','',$line); //ignore comments
        $line = trim($line);
        if(empty($line)) continue;

        $row    = explode(":",$line,2);
        $keys = array_values(array_filter(explode(",",$row[1])));

        $this->yubikeys[$row[0]] = $keys;
      }
    }
}

/*********************************************

Requires PHP 5

Class: Yubikey Authentication
Author: Tom Corwine (yubico@corwine.org)
License: GPL-2
Version: 0.96

Class should be instantiated with your Yubico API id and, optionally, the signature key.

Example:
$var = new Yubikey(int id, [string signature key]);

If you don't specifiy a signature key, the signature verification steps are skipped.


Methods:

->getid(string) - Accepts otp from Yubikey. Returns the 12-character id sequence of the key.
->verify(string) - Accepts otp from Yubikey. Returns TRUE for authentication success, otherwise FALSE.
->getLastResponse() - Returns response message from verification attempt.
->getTimestampTolerance() - Gets the tolerance (+/-, in seconds) for timestamp verification.
->setTimestampTolerance(int) - Sets the tolerance (in seconds, 0-86400) - default 600 (10 minutes).
	Returns TRUE on success and FALSE on failure.
->getCurlTimeout() - Gets the timeout (in seconds) CURL uses before giving up on contacting Yubico's server.
->setCurlTimeout(int) - Sets the CURL timeout (in seconds, 0-600, 0 means indefinitely) - default 10.
	Returns TRUE on success and FALSE on failure.

*********************************************/
class Yubikey
{
	// Input
	private $_id;
	private $_signatureKey;

	// Output
	private $_response;

	// Internal
	private $_curlResult;
	private $_curlError;
	private $_timestampTolerance;
	private $_curlTimeout;

	/****************************************************************************
	Public Methods
	****************************************************************************/

	public function __construct($id, $signatureKey = null)
	{
		if (is_int ($id) && $id > 0) $this->_id = $id;

		if (strlen ($signatureKey) == 28)
		{
			$this->_signatureKey = base64_decode ($signatureKey);
		}

		// Set defaults
		$this->_timestampTolerance = 600; //Seconds
		$this->_curlTimeout = 10; //Seconds
	}

	public function getTimestampTolerance()
	{
		return $this->_timestampTolerance;
	}

	public function setTimestampTolerance($int)
	{
		if ($int > 0 && $int < 86400)
		{
			$this->_timestampTolerance = $int;
			return true;
		}
		else
		{
			return false;
		}
	}

	public function getCurlTimeout()
	{
		return $this->_curlTimeout;
	}

	public function setCurlTimeout($int)
	{
		if ($int > 0 && $int < 600)
		{
			$this->_curlTimeout = $int;
			return true;
		}
		else
		{
			return false;
		}
	}

	public function getLastResponse()
	{
		return $this->_response;
	}

	public function getid($otp)
	{
		return substr($otp, 0, 12);
	}

	public function verify($otp)
	{
		unset ($this->_response);
		unset ($this->_curlResult);
		unset ($this->_curlError);

		$otp = strtolower ($otp);

		if (!$this->_id)
		{
			$this->_response = "ID NOT SET";
			return false;
		}

		if (!$this->otpIsProperLength($otp))
		{
			$this->_response = "BAD OTP LENGTH";
			return false;
		}

		if (!$this->otpIsModhex($otp))
		{
			$this->_response = "OTP NOT MODHEX";
			return false;
		}

		$urlParams = "id=".$this->_id."&otp=".$otp;

		$url = $this->createSignedRequest($urlParams);

		if ($this->curlRequest($url)) //Returns 0 on success
		{
			$this->_response = "ERROR CONNECTING TO YUBICO - ".$this->_curlError;
			return false;
		}

		foreach ($this->_curlResult as $param)
		{
			if (substr ($param, 0, 2) == "h=") $signature = substr (trim ($param), 2);
			if (substr ($param, 0, 2) == "t=") $timestamp = substr (trim ($param), 2);
			if (substr ($param, 0, 7) == "status=") $status = substr (trim ($param), 7);
		}

		// Concatenate string for signature verification
		$signedMessage = "status=".$status."&t=".$timestamp;

		if (!$this->resultSignatureIsGood($signedMessage, $signature))
		{
			$this->_response = "BAD RESPONSE SIGNATURE";
			return false;
		}

		if (!$this->resultTimestampIsGood($timestamp))
		{
			$this->_response = "BAD TIMESTAMP";
			return false;
		}

		if ($status != "OK")
		{
			$this->_response = $status;
			return false;
		}

		// Everything went well - We pass
		$this->_response = "OK";
		return true;
	}

	/****************************************************************************
	Protected methods
	****************************************************************************/

	protected function createSignedRequest($urlParams)
	{
		if ($this->_signatureKey)
		{
			$hash = urlencode (base64_encode (hash_hmac ("sha1", $urlParams, $this->_signatureKey, true)));
			return "https://api.yubico.com/wsapi/verify?".$urlParams."&h=".$hash;
		}
		else
		{
			return "https://api.yubico.com/wsapi/verify?".$urlParams;
		}
	}

	protected function curlRequest($url)
	{
		$ch = curl_init ($url);

		curl_setopt ($ch, CURLOPT_TIMEOUT, $this->_curlTimeout);
		curl_setopt ($ch, CURLOPT_CONNECTTIMEOUT, $this->_curlTimeout);
		curl_setopt ($ch, CURLOPT_FOLLOWLOCATION, false);
		curl_setopt ($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt ($ch, CURLOPT_SSL_VERIFYHOST, 2);
		curl_setopt ($ch, CURLOPT_SSL_VERIFYPEER, true);

		$this->_curlResult = explode ("\n", curl_exec($ch));

		$this->_curlError = curl_error ($ch);
		$error = curl_errno ($ch);

		curl_close ($ch);

		return $error;
	}

	protected function otpIsProperLength($otp)
	{
		if (strlen ($otp) == 44)
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	protected function otpIsModhex($otp)
	{
		$modhexChars = array ("c","b","d","e","f","g","h","i","j","k","l","n","r","t","u","v");

		foreach (str_split ($otp) as $char)
		{
			if (!in_array ($char, $modhexChars)) return false;
		}

		return true;
	}

	protected function resultTimestampIsGood($timestamp)
	{
		// Turn times into 'seconds since Unix Epoch' for easy comparison
		$now = date ("U");
		$timestampSeconds = (date_format (date_create (substr ($timestamp, 0, -4)), "U"));

		// If date() functions above fail for any reason, so do we
		if (!$timestamp || !$now) return false;

		if (($timestampSeconds + $this->_timestampTolerance) > $now &&
		    ($timestampSeconds - $this->_timestampTolerance) < $now)
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	protected function resultSignatureIsGood($signedMessage, $signature)
	{
		if (!$this->_signatureKey) return true;

		if (base64_encode (hash_hmac ("sha1", $signedMessage, $this->_signatureKey, true)) == $signature)
		{
			return true;
		}
		else
		{
			return false;
		}
	}
}
