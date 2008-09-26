<?php
define('S_OK', 'OK');
define('S_BAD_OTP', 'BAD_OTP');
define('S_BAD_CLIENT', 'BAD_CLIENT'); // New, added by paul 20080920
define('S_REPLAYED_OTP', 'REPLAYED_OTP');
define('S_BAD_SIGNATURE', 'BAD_SIGNATURE');
define('S_MISSING_PARAMETER', 'MISSING_PARAMETER');
//define('S_NO_SUCH_CLIENT', 'NO_SUCH_CLIENT'); // Deprecated by paul 20080920
define('S_OPERATION_NOT_ALLOWED', 'OPERATION_NOT_ALLOWED');
define('S_BACKEND_ERROR', 'BACKEND_ERROR');

function debug($msg, $exit = false) {
	global $trace;
	if ($trace) {
		if (is_array($msg)) {
			print_r($msg);
		} else {
			echo 'debug> ' . $msg;
		}
		echo "\n";
	}
	if ($exit) {
		die('<font color=red><h4>Exit</h4></font>');
	}
}

function genRandRaw($len) {
	$h = hash_hmac('sha1', rand(9999,9999999), 'dj*ccbcuiiurubrvnubcdluul', true);
	$a = str_split($h);
	//print_r($a);
	$a = array_slice($a, 0, $len);
	//print_r($a);
	$s = implode($a);
	//outputToFile('out', $s);
	return $s;
}

function outputToFile($outFname, $content, $mode, $append = false) {
	$out = fopen($outFname, ($append ? "a" : "w"));
	fwrite($out, $content);
	fclose($out);
}
?>
