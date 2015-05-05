<?php

class SignedRequest
{
	public static function parse($secret, $request)
	{
		if (!strpos($request, '.')) {
			throw new Exception('Invalid request.');
		}

		list($signature, $payload) = explode('.', $request, 2);
		$sig = static::base64UrlDecode($signature);
		$data = json_decode(static::base64UrlDecode($payload), true);

		$expectedSig = static::createSignature($payload, $secret);
		if ($sig !== $expectedSig) {
			return null;
		}

		return $data;
	}

	public static function sign($secret, $body)
	{
		$data = static::base64UrlEncode(json_encode($body));
		$signature = static::createSignature($data, $secret);

		return sprintf('%s.%s', static::base64UrlEncode($signature), $data);
	}

	public static function isAuthentic($secret, $request)
	{
		return static::parse($secret, $request) !== null;
	}

	protected static function createSignature($data, $secret)
	{
		return hash_hmac('sha256', $data, $secret, false);
	}

	protected static function base64UrlDecode($input) {
		return base64_decode(strtr($input, '-_', '+/'));
	}

	protected static function base64UrlEncode($input) {
		return base64_encode(strtr($input, '+/', '-_'));
	}
}



