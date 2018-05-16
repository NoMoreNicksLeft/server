<?php
declare(strict_types=1);
/**
 * @copyright Copyright 2018, Roeland Jago Douma <roeland@famdouma.nl>
 *
 * @author Roeland Jago Douma <roeland@famdouma.nl>
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
namespace OC\Authentication\Token;

use OC\Authentication\Exceptions\InvalidTokenException;

class ExpiredTokenException extends InvalidTokenException {
	/** @var IToken */
	private $token;

	public function __construct(IToken $token) {
		parent::__construct();

		$this->token = $token;
	}

	public function getToken(): IToken {
		return $this->token;
	}
}
