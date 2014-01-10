<?php
namespace wcf\system\user\authentication;
use wcf\data\user\group\UserGroup;
use wcf\data\user\UserAction;
use wcf\data\user\User;
use wcf\data\user\UserEditor;
use wcf\data\user\UserProfileAction;
use wcf\system\exception\SystemException;
use wcf\system\exception\UserInputException;
use wcf\util\HeaderUtil;
use wcf\util\PasswordUtil;
use wcf\system\database\MySQLDatabase;
use wcf\system\database\PostgreSQLDatabase;
use wcf\util\LDAPUtil;
use wcf\util\UserUtil;
use wcf\system\language\LanguageFactory;
use wcf\system\WCF;

/**
 * @author      Jan Altensen (Stricted)
 * @copyright   2013-2014 Jan Altensen (Stricted)
 * @license     GNU Lesser General Public License <http://opensource.org/licenses/lgpl-license.php>
 * @package     be.bastelstu.jan.wcf.auth.extendet
 * @category    Community Framework
 */
class UserLDAPAuthentication extends UserAbstractAuthentication {

	/**
	 * Checks the given user data.
	 *
	 * @param	string		$username
	 * @param 	string		$password
	 * @return	boolean
	 */
	protected function login ($username, $password) {
		$ldap = new LDAPUtil();
		// connect
		$connect = $ldap->connect(AUTH_TYPE_LDAP_SERVER, AUTH_TYPE_LDAP_SERVER_PORT, AUTH_TYPE_LDAP_SERVER_DN);
		if ($connect) {
			// find user
			if ($ldap->bind($username, $password)) {
				// try to find user email
				if (($search = $ldap->search('uid='.$username))) {
					$results = $ldap->get_entries($search);
					if (isset($results[0]['mail'][0])) {
						$this->email = $results[0]['mail'][0];
					}
				}
				
				$ldap->close();
				return true;
			} elseif ($this->isValidEmail($username) && ($search = $ldap->search('mail='.$username))) {
				$results = $ldap->get_entries($search);
				if(isset($results[0]['uid'][0])) {
					$this->username = $results[0]['uid'][0];
					$ldap->close($connect);
					return $this->login($this->ldapusername, $password);
				}
			}
		}
		// no ldap user or connection -> check user from wcf
		$ldap->close($connect);
		if(AUTH_CHECK_WCF) {
			return $this->checkWCFUser($username, $password);
		}
		return false;
	}
}
?>