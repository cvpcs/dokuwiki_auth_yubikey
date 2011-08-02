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
require_once(DOKU_INC.'inc/Yubikey.php');

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
        $otpid = $this->getOtpId($otp);

        // make sure the key we're using is assigned to this user
        if (in_array($otpid, $yubiinfo))
        {
          // attempt a verification
          $yubikey = new Yubikey(AUTH_YUBIKEY_API_ID);
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

    function getOtpId($otp) {
      return substr($otp, 0, 12);
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
