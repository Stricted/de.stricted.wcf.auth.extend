<?php
/* LDAPUtil.class.php - de.stricted.auth.wcf.extend
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
namespace wcf\util;
use wcf\system\WCF;
use wcf\system\exception\SystemException;

class LDAPUtil {
	/**
	 * LDAP resource id
	 */
	protected $ldap = Null;	
	
	/**
	 * LDAP DN
	 */
	protected $dn = '';
	
	/**
	 * Constructs a new instance of LDAPUtil.
	 */
	public function __construct () {
		if(!extension_loaded("ldap")) {
			throw new SystemException("Can not find LDAP extension.");
		}
	}
	
	/**
	 * connect to a ldap server
	 *
	 * @param	string	$server
	 * @param	integer	$port
	 * @param	string	$dn
	 * @return	bool	true/false
	 */
	public function connect ($server, $port, $dn) {
		$this->ldap = @ldap_connect($server, $port);
		$this->dn = $dn;
		if($this->ldap) {
			ldap_set_option($this->ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
			ldap_set_option($this->ldap, LDAP_OPT_REFERRALS, 0);
			return true;
		}
		return false;
	}
	
	/**
	 *	returns ldap user array
	 *
	 *	@param	string	$user
	 *	@param	string	$password
	 *	@return	array
	 */
	public function bind ($user, $password) {
		return @ldap_bind($this->ldap, "uid=".$user.",".$this->dn, $password);
	}
	
	/**
	 *	search user on ldap server
	 *
	 * @param	string	$search
	 * @return	resource
	 */
	public function search ($search) {
		return ldap_search($this->ldap, $this->dn, $search);
	}
	
	/**
	 * get entries from search resource
	 *
	 * @param	resource	$resource
	 * @return	array
	 */
	public function get_entries ($resource) {
		return ldap_get_entries($this->ldap, $resource);
	}
	
	/**
	 * close ldap connection
	 */
	public function close () {
		ldap_close($this->ldap);
	}
}
?>