<?php
/* UserDBAuthentication.class.php - de.stricted.auth.wcf.extend
 * Copyright (C) 2013 Jan Altensen (Stricted)
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>. 
 */
// imports
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