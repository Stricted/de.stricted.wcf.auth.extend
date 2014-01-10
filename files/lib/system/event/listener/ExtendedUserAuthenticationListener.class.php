<?php
namespace wcf\system\event\listener;
use wcf\system\event\IEventListener;
use wcf\system\WCF;

/**
 * @author      Jan Altensen (Stricted)
 * @copyright   2013-2014 Jan Altensen (Stricted)
 * @license     GNU Lesser General Public License <http://opensource.org/licenses/lgpl-license.php>
 * @package     be.bastelstu.jan.wcf.auth.extendet
 * @category    Community Framework
 */
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