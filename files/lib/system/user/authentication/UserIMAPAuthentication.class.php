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
class UserIMAPAuthentication extends UserAbstractAuthentication {

	/**
	 * Checks the given user data.
	 *
	 * @param	string		$username
	 * @param 	string		$password
	 * @return	boolean
	 */
	protected function login ($username, $password) {
		if(!extension_loaded("imap")) {
			throw new SystemException("Can not find IMAP extension.");
		}
		if($this->isValidEmail($username)) {
			$options = '{'.AUTH_TYPE_IMAP_HOST.':'.AUTH_TYPE_IMAP_PORT.AUTH_TYPE_IMAP_BASEOPTIONS.'}';
			$conn = @imap_open($options, $username, $password, OP_HALFOPEN);
			if($conn) {
				$this->email = $username;
				@imap_close($conn);
				return true;
			}
			@imap_close($conn);
			if(AUTH_CHECK_WCF) {
				return $this->checkWCFUser($username, $password);
			}
		}
		return false;
	}
}
?>