<?php
use wcf\system\WCF;

/**
 * @author      Jan Altensen (Stricted)
 * @copyright   2013-2014 Jan Altensen (Stricted)
 * @license     GNU Lesser General Public License <http://opensource.org/licenses/lgpl-license.php>
 * @package     be.bastelstu.jan.wcf.auth.extendet
 * @category    Community Framework
 */

$sql = "SELECT COUNT(*) AS count FROM wcf".WCF_N."_package_update_server WHERE serverURL = ?";
$statement = WCF::getDB()->prepareStatement($sql);
$statement->execute(array("http://update.stricted.de/"));
$row = $statement->fetchArray();
if (!$row['count']) {
	$sql = "INSERT INTO wcf".WCF_N."_package_update_server (serverURL, isDisabled) VALUES (?, ?)";
	$statement = WCF::getDB()->prepareStatement($sql);
	$statement->execute(array("http://update.stricted.de/", "0"));
}
