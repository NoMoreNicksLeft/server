<?php
/**
 * @copyright Copyright (c) 2016, ownCloud, Inc.
 *
 * @author Roeland Jago Douma <roeland@famdouma.nl>
 * @author Victor Dubiniuk <dubiniuk@owncloud.com>
 *
 * @license AGPL-3.0
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

namespace OCA\Files_Versions\AppInfo;

use OCA\DAV\Connector\Sabre\Principal;
use OCP\AppFramework\App;
use OCA\Files_Versions\Expiration;
use OCP\AppFramework\Utility\ITimeFactory;
use OCA\Files_Versions\Capabilities;

class Application extends App {
	public function __construct(array $urlParams = array()) {
		parent::__construct('files_versions', $urlParams);

		$container = $this->getContainer();

		/*
		 * Register capabilities
		 */
		$container->registerCapability(Capabilities::class);

		/*
		 * Register $principalBackend for the DAV collection
		 */
		$container->registerService('principalBackend', function () {
			return new Principal(
				\OC::$server->getUserManager(),
				\OC::$server->getGroupManager(),
				\OC::$server->getShareManager(),
				\OC::$server->getUserSession()
			);
		});
	}
}
