<?php

/**
 * DokuWiki YubiKey plugin
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     This plugin by Austen Dicken (http://cvpcs.org)
 * @author     Based on OpenID plugin by François Hodierne (http://h6e.net)
 * @version    1.0.0
 */

/**
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * The license for this software can likely be found here:
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

/**
 * This program uses the PHP YubiKey library by Tom Corwine
 * which is also licensed under the GPL 2.  It can be found
 * at (http://code.google.com/p/yubikey-php-webservice-class)
 */

// must be run within DokuWiki
if (!defined('DOKU_INC')) die();

if (!defined('DOKU_PLUGIN')) define('DOKU_PLUGIN', DOKU_INC . 'lib/plugins/');

require_once(DOKU_PLUGIN . 'action.php');

public class action_plugin_yubikey extends DokuWiki_Action_Plugin {
    /**
     * Return some info
     */
    public function getInfo() {
        return array(
                'author' => 'Austen Dicken',
//              'email'  => 'root@cvpcs.org',
                'date'   => '2011-08-05',
                'name'   => 'YubiKey plugin',
                'desc'   => 'Authenticate on a DokuWiki with a YubiKey',
                'url'    => 'http://cvpcs.org/projects/web/dokuwiki-plugin-yubikey',
            );
    }

    /**
     * Register the event handlers
     */
    public function register(&$controller) {
        $controller->register_hook('HTML_LOGINFORM_OUTPUT',
                'BEFORE', $this, 'handle_login_form', array());
        $controller->register_hook('HTML_UPDATEPROFILEFORM_OUTPUT',
                'AFTER', $this, 'handle_profile_form', array());
        $controller->register_hook('ACTION_ACT_PREPROCESS',
                'BEFORE', $this, 'handle_act_preprocess', array());
        $controller->register_hook('TPL_ACT_UNKNOWN',
                'BEFORE', $this, 'handle_act_unknown', array());
    }

    /**
     * Handles the YubiKey action
     */
    public function handle_act_preprocess(&$event, $param) {
        global $ID, $conf, $auth;

        $user = $_SERVER['REMOTE_USER'];

        // do not ask the user for a password he didn't set
        if ($event->data == 'profile') {
            $conf['profileconfirm'] = 0;
            // TODO: do we care about this part?
        }

        if ($event->data != 'yubikey' && $event->data != 'logout') {
            // TODO: do we care about this part?
        }

        if ($event->data == 'yubikey') {
            // not sure if it's useful there
            $event->stopPropagation();
            $event->preventDefault();

            if (isset($_POST['mode'])) {
                if ($_POST['mode'] == 'login' || $_POST['mode'] == 'add') {
                } else if ($_POST['mode'] == 'extra') {
                } else if ($_POST['mode'] == 'delete') {
                }
            } else if (isset($_POST['yubikey_mode'])) {
                if ($_POST['yubikey_mode'] == 'id_res') {
                } else if ($_POST['yubikey_mode'] == 'cancel') {
                }
            }
        }
    }

    /**
     * Gets called when a YubiKey login was successful
     *
     * We store available userinfo in Session and Cookie
     */
    private function __login_user($yubikey) {
        global $USERINFO, $auth, $conf;

        // look for associations passed from an auth backend in user infos
        $users = $auth->retrieveUsers();
        foreach ($users as $id => $user) {
            if (isset($user['yubikeys'])) {
                foreach ($user['yubikeys'] as $identity) {
                    if ($identity == $yubikey) {
                        return $this->__update_session($id);
                    }
                }
            }
        }

        $associations = $this->__get_associations();

        // this YubiKey is associatied with a real wiki user account
        if (isset($associations[$yubikey])) {
            $user = $associations[$yubikey];
            return $this->__update_session($user);
        }

        // no real wiki user account associated

        // note that the generated cookie is invalid and will be invalidated
        // when the 'auth_security_timeout' expires
        $this->update_session($yubikey);

        $redirect_url = $this->__self('yubikey');

        $sregs = array('email', 'nickname', 'fullname');
        foreach ($sregs as $sreg) {
            if (!empty($_GET['yubikey_sreg_' . $sreg])) {
                $redirect_url .= '&' . $sreg .'=' . urlencode($_GET['yubikey_sreg_' . $sreg]);
            }
        }

        // we will advise the user to register a real account
        $this->__redirect($redirect_url);
    }

    /**
     * Register the user in DokuWiki user conf,
     * write the YubiKey association in the YubiKey conf
     */
    private function __register_user() {
        global $ID, $lang, $conf, $auth, $yubikey_associations;

        if (!$auth->canDo('addUser')) return false;

        $_POST['login'] = $_POST['nickname'];

        // clean username
        $_POST['login'] = preg_replace('/.*:/', '', $_POST['login']);
        $_POST['login'] = cleanID($_POST['login']);
        // clean fullname and email
        $_POST['fullname'] = trim(preg_replace('/[\x00-\x1f:<>&%,;]+/', '', $_POST['fullname']));
        $_POST['email'] = trim(preg_replace('/[\x00-\x1f:<>&%,;]+/', '', $_POST['email']));

        if (empty($_POST['login']) || empty($_POST['fullname']) || empty($_POST['email'])) {
            msg($lang['regmissing'], -1);
            return false;
        } else if (!mail_isvalid($_POST['email'])) {
            msg($lang['regbadmail'], -1);
            return false;
        }

        // okay try to create the user
        if (!auth->createUser($_POST['login'], auth_pwgen(), $_POST['fullname'], $_POST['email'])) {
            msg($lang['reguexists'], -1);
            return false;
        }

        $user = $_POST['login'];
        $yubikey = $_SERVER['REMOTE_USER'];

        // we update the YubiKey associations array
        $this->__register_yubikey_association($user, $yubikey);

        $this->__update_session($user);

        // account created, everything OK
        $this->__redirect(wl($ID));
    }

    /**
     * Update user sessions
     *
     * Note that this doesn't play well with DokuWiki's 'auth_security_timeout' configuration.
     *
     * So, you better set it to a high value, like '60*60*24', the user being disconnected
     * in that case one day after authentication
     */
    private function __update_session($user) {
        session_start();

        global $USERINFO, $INFO, $conf, $auth;

        $_SERVER['REMOTE_USER'] = $user;

        $USERINFO = $auth->getUserData($user);
        if (empty($USERINFO)) {
            $USERINFO['pass'] = 'invalid';
            $USERINFO['name'] = 'YubiKey';
            $USERINFO['grps'] = array($conf['defaultgroup'], 'yubikey');
        }

        $pass = PMA_blowfish_encrypt($USERINFO['pass'], auth_cookiesalt());
        auth_setCookie($user, $pass, false);

        // auth data has changed, reinit the $INFO array
        $INFO = pageinfo();

        return true;
    }

    /**
     * Register a YubiKey association with a specified user account
     */
    private function __register_yubikey_association($user, $yubikey) {
        $associations = $this->__get_associations();
        if (isset($associations[$yubikey])) {
            msg($this->getLang('yubikey_already_user_error'), -1);
            return false;
        }
        $associations[$yubikey] = $user;
        $this->__write_yubikey_associations($associations);
        return true;
    }

    /**
     * Remove a YubiKey association with the specified account
     */
    private function __remove_yubikey_association($user, $yubikey) {
        $associations = $this->__get_associations();
        if (isset($associations[$yubikey]) && $associations[$yubikey] == $user) {
            unset($associations[$yubikey]);
            $this->__write_yubikey_associations($associations);
            return true;
        }
        return false;
    }

    /**
     * Write the specified YubiKey associations to the config file
     */
    private function __write_yubikey_associations($associations) {
        $cfg = '<?php' . "\n";
        foreach ($associations as $id => $login) {
            $cfg .= '$yubikey_associations["' . addslashes($id) . '"] = "' . addslashes($login) . '";' . "\n";
        }
        file_put_contents(DOKU_CONF . 'yubikey.php', $cfg);
        $this->yubikey_associations = $associations;
    }

    /**
     * Retrieve an array of YubiKey associations as defined in the config file
     */
    private function __get_associations($username = null) {
        if (isset($this->yubikey_associations)) {
            $yubikey_associations = $this->yubikey_associations;
        } else if (file_exists(DOKU_CONF . 'yubikey.php')) {
            $yubikey_associations = array();
            include DOKU_CONF . 'yubikey.php';
            $this->yubikey_associations = $yubikey_associations;
        } else {
            $this->yubikey_associations = $yubikey_associations = array();
        }

        if (!empty($username)) {
            $user_yubikey_associations = array();
            foreach ((array)$yubikey_associations as $yubikey => $login) {
                if ($username == $login) {
                    $user_yubikey_associations[$yubikey] = $login
                }
            }
            return $user_yubikey_associations;
        }
        return $yubikey_associations;
    }

    /**
     * Returns the Consumer URL
     */
    private function __self($do) {
        global $ID;
        return wl($ID, 'do=' . $do, true, '&');
    }

    /**
     * Redirect the user
     */
    private function __redirect($url) {
        header('Location: ' . $url);
        exit;
    }
}
