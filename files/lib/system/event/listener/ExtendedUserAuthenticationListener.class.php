<?php
/* ExtendedUserAuthenticationListener.class.php - de.stricted.wcf.auth.extend
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
namespace wcf\system\event\listener;
use wcf\system\event\IEventListener;
use wcf\system\WCF;


class ExtendedUserAuthenticationListener implements IEventListener {
	/**
	 * @see EventListener::execute()
	 */
	public function execute($eventObj, $className, $eventName) {
		if (AUTH_TYPE != 'Default') {
			$eventObj->className = 'wcf\system\user\authentication\User'.AUTH_TYPE.'Authentication';
		}
	}
}
?>