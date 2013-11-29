<?php
/* UserIMAPAuthentication.class.php - de.stricted.auth.extend
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