<?php
/* UserRadiusAuthentication.class.php - de.stricted.auth.wcf.extend
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

class UserRadiusAuthentication extends UserAbstractAuthentication {

	/**
	 * Checks the given user data.
	 *
	 * @param	string		$username
	 * @param 	string		$password
	 * @return	boolean
	 */
	protected function login ($username ,$password) {
		if(!extension_loaded("radius")) {
			throw new SystemException("Can not find LDAP extension.");
		}
		if($radius = radius_auth_open()) {
			if (radius_add_server($radius, AUTH_TYPE_RADIUS_HOST, AUTH_TYPE_RADIUS_PORT, AUTH_TYPE_RADIUS_SECRET,5,3)) {
				if (radius_create_request($radius,RADIUS_ACCESS_REQUEST)) {
					radius_put_attr($radius,RADIUS_USER_NAME, $username);
					radius_put_attr($radius,RADIUS_USER_PASSWORD, $password);
					$return = radius_send_request($radius);
					if($return == RADIUS_ACCESS_ACCEPT) {
						if($this->isValidEmail($username)) {
							$this->email = $username;
						} else {
							$this->email = $username."@radius.dummy";
						}
						return true;
					}
				} else {
					throw new SystemException("Radius Error: ".radius_strerror($radius));
				}
			} else {
				throw new SystemException("Radius Error: ".radius_strerror($radius));
			}
		}
		if(AUTH_CHECK_WCF) {
			return $this->checkWCFUser($username, $password);
		}
		return false;
	}
}
?>