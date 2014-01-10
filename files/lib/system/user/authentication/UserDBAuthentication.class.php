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
class UserDBAuthentication extends UserAbstractAuthentication {

	/**
	 * Checks the given user data.
	 *
	 * @param	string		$username
	 * @param 	string		$password
	 * @return	boolean
	 */
	protected function login ($username, $password) {
		$className = 'wcf\system\database\\'.AUTH_DB_TYPE.'Database';
		$db = new $className(AUTH_DB_HOST, AUTH_DB_USER, AUTH_DB_PASSWORD, AUTH_DB_NAME, AUTH_DB_PORT);
		if(AUTH_DB_HASH_METHOD != "plain") {
			$hashmethod = AUTH_DB_HASH_METHOD;
			$hashedpw = $hashmethod($password);
		} else { $hashedpw = $password; }
		if($this->isValidEmail($username)) {
			$sql = "SELECT	".AUTH_DB_FIELDNAME_USER.", ".AUTH_DB_FIELDNAME_EMAIL."
				FROM	".AUTH_DB_TABLENAME."
				WHERE	".AUTH_DB_FIELDNAME_EMAIL." = ':user'
				AND		".AUTH_DB_FIELDNAME_PASSWORD." = ':password'";
		} else {
			$sql = "SELECT	".AUTH_DB_FIELDNAME_USER.", ".AUTH_DB_FIELDNAME_EMAIL."
				FROM	".AUTH_DB_TABLENAME."
				WHERE	".AUTH_DB_FIELDNAME_USER." = ':user'
				AND		".AUTH_DB_FIELDNAME_PASSWORD." = ':password'";
		}
		$statement = $db->prepareStatement($sql);
		$statement->execute(array(":user" => $username, ":password" => $hashedpw));
		$row = $statement->fetchArray();
		if (!empty($row[AUTH_DB_FIELDNAME_USER]) && !empty($row[AUTH_DB_FIELDNAME_EMAIL])) {
				$this->email = $row[AUTH_DB_FIELDNAME_EMAIL];
				if($this->isValidEmail($username)) {
					$this->username = $row[AUTH_DB_FIELDNAME_USER];
				}
				return true;
		}
		if(AUTH_CHECK_WCF) {
			return $this->checkWCFUser($username, $password);
		}
		return false;
	}
}
?>