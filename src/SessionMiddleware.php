<?php

namespace Adbar;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;


/**
 * Session Middleware
 *
 * This middleware class starts a secure session and encrypts it if encryption key is set.
 * Session cookie path, domain and secure values are configured automatically by default.
 */
final class SessionMiddleware implements MiddlewareInterface
{
	/** @var array Default settings */
	protected $settings = [

		// Session cookie settings
		'name' => 'slim_session',
		'lifetime' => 24,
		'path' => '/',
		'domain' => null,
		'secure' => false,
		'httponly' => true,

		// Set session cookie path, domain and secure automatically
		'cookie_autoset' => true,

		// Path where session files are stored, PHP's default path will be used if set null
		'save_path' => null,

		// Session cache limiter
		'cache_limiter' => 'nocache',

		// Extend session lifetime after each user activity
		'autorefresh' => false,

		// Encrypt session data if string is string is set
		'encryption_key' => null,

		// Session namespace
		'namespace' => 'slim_app'
	];

	private $session;

	/**
	 * Constructor
	 *
	 * @param array $settings Session settings
	 */
	public function __construct(\Adbar\Session &$session, array $settings = [])
	{
		$this->session = $session;
		$this->settings = array_merge($this->settings, $settings);
	}

	/**
	 * Invoke middleware
	 *
	 * @param  ServerRequestInterface  $request
	 * @param  RequestHandlerInterface $handler
	 *
	 * @return ResponseInterface
	 */
	public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
	{
		// Get settings from request
		if ($this->settings['cookie_autoset'] === true) {
			$this->settings['path'] = $request->getUri()->getBasePath() . '/';
			$this->settings['domain'] = $request->getUri()->getHost();
			$this->settings['secure'] = $request->getUri()->getScheme() === 'https' ? true : false;
		}

		// Start session
		$this->start($request);

		// Next middleware
		return $handler->handle($request);
	}

	/**
	 * Configure and start session
	 *
	 * @param Request $request PSR7 request
	 */
	protected function start(ServerRequestInterface $request)
	{
		$this->session->initialize($this->settings, $request->getHeaderLine('HTTP_USER_AGENT'));
		$this->session->start();
		$this->refreshSessionCookie();
	}

	protected function refreshSessionCookie()
	{
		if ($this->settings['autorefresh'] === true && isset($_COOKIE[$this->settings['name']])) {
			setcookie(
				$this->settings['name'],
				$_COOKIE[$this->settings['name']],
				time() + $this->settings['lifetime'],
				$this->settings['path'],
				$this->settings['domain'],
				$this->settings['secure'],
				$this->settings['httponly']
			);
		}
	}
}
