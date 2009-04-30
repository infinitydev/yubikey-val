<?php require_once '../yubiphpbase/appinclude.php';
	  require_once '../yubiphpbase/yubi_lib.php';
	  require_once 'common.php';
	  
header("content-type: text/plain");

if (!isset ($trace)) {
	$trace = 0;
}

$client = getHttpVal('id', 0);
if ($client <= 0) {
	debug('Client ID is missing');
	sendResp(S_MISSING_PARAMETER, 'id');
	exit;
}

$otp = getHttpVal('otp', '');
if ($otp == '') {
	debug('OTP is missing');
	sendResp(S_MISSING_PARAMETER, 'otp');
	exit;
} else {
	$otp = strtolower($otp);
}

//// Get device ID from OTP
//
$devId = substr($otp, 0, 12);

//// Get the user Name
//
$userName = getHttpVal('un', '');
if ($userName == '') {
	/// No need to verify the username and yubikeyId mapping
	debug('user name is missing');
} else {
	/// verify the username and yubikeyId mapping 
	$keyMap = getKeyMapInfo($client, $userName, $devId);

	if ($keyMap == null) {
		debug('Invalid Yubikey '.$userName);
		if(isAutoProvisionEnabled($client)) {
			debug(' Auto-Provision is enabled '.$client);
			$respMap = isTokenMapped($userName, $devId);
			if($respMap == 0){
				// chk for cmd=add parameter ?.....
				//
				$command = getHttpVal('cmd', '');
				if ($command == 'add') {
					/// No need to verify the username and yubikeyId mapping
					/// addUserMap
					debug(' Adding user mapping for '.$devId);
					if(!addUserMap($userName, $devId)) {
						debug('Error occurred while adding user and token ID mapping');
					}
				} else {
					sendResp(S_NO_USERMAP, $userName);
					exit;
				}
			} else {
				// S_BAD_USERSETTING
				debug(' Token Already mapped '.$devId.' RespMap '.$respMap);
				sendResp(S_BAD_USERKEY, $userName);
				exit;
			}
			
		} else {
			debug(' Auto-Provision is not enabled '.$client);
			sendResp(S_BAD_USERKEY, $userName);
			exit;
		}
	} else {
		debug($keyMap);
		/// S_BAD_USERSETTING chk the user settings 
		debug(' User map validation Type '.$keyMap['validity_type'].' And '.$keyMap['end_date']);
		if (!$keyMap['user_status']) {
			debug(' User is not active '.$userName);
			sendResp(S_BAD_USERSETTING, $userName);
			exit;
		} else if (!$keyMap['map_status']) {
			debug(' User map is not active '.$userName);
			sendResp(S_BAD_USERSETTING, $userName);
			exit;
			
		} else if ($keyMap['validity_type'] == 'demo') {
			// check for validity time 
			$user_last_date = strtotime($keyMap['end_date']);
			date_default_timezone_set('UTC'); 
			$current_date = strtotime(date("Y-m-d H:i:s"));
			debug(' User map date check '.$user_last_date.' And '.$current_date);
			if ($current_date > $user_last_date) {
				debug(' User map date expire '.$userName);
				sendResp(S_BAD_USERSETTING, $userName);
				exit;
			}
		} 
	}
}

//// Get Yubikey from DB
//
$ad = getAuthData($devId);

if ($ad == null) {
	debug('Invalid Yubikey ' . $devId);
	sendResp(S_BAD_OTP, $otp);
	exit;
} else {
	debug($ad);
}

//// Check the client ID - does the client own the Yubikey?
//

if ($ad['chk_owner'] && $ad['client_id'] != $client) {
	debug('Client-' . $client . ' is not the owner of the Yubikey!');
	sendResp(S_BAD_CLIENT, 'Not owner of the Yubikey');
	exit;
}

$k = b64ToModhex($ad['secret']);
//debug('aes key in modhex = '.$k);
$key16 = ModHex :: Decode($k);
//debug('aes key in hex = ['.$key16.'], length = '.strlen($key16));
$apiKey = base64_decode($ad['c_secret']);

//// Check signature
//
$h = getHttpVal('h', '');

if ($ad['chk_sig'] && $h == '') {
	sendResp(S_MISSING_PARAMETER, 'h');
	debug('Signature missing');
	exit;
} else if ($ad['chk_sig'] || $h != '') {
	// Create the signature using the API key
	$a = array ();
	$a['id'] = $client;
	$a['otp'] = $otp;
	$hmac = sign($a, $apiKey);

	// Compare it
	if ($hmac != $h) {
		sendResp(S_BAD_SIGNATURE);
		debug('client hmac=' . $h . ', server hmac=' . $hmac);
		exit;
	}
}

//// Decode OTP from input
//
debug('OTP validation req:');
$decoded_token = Yubikey :: Decode($otp, $key16);
debug($decoded_token);
if (!is_array($decoded_token)) {
	sendResp(S_BAD_OTP, $otp);
	exit;
}

//// Sanity check key status
//
if ($ad['active'] < 1) {
	sendResp(S_BAD_OTP, 'Suspended');
	exit;
}

//// Sanity check client status
//
if ($ad['c_active'] < 1) {
	sendResp(S_BAD_CLIENT);
	exit;
}

//// Sanity check token ID
//
if (strlen($decoded_token["public_id"]) == 12) {
	debug("Token ID OK (" . $decoded_token["public_id"] . ")");
} else {
	debug("TOKEN ID FAILED, " . $decoded_token["public_id"]);
	sendResp(S_BAD_OTP, $otp);
	exit;
}

//// Sanity check the OTP
//
if (strlen($decoded_token["token"]) != 32) {
	debug("Wrong OTP length," . strlen($decoded_token["token"]));
	sendResp(S_BAD_OTP, $otp);
	exit;
}

//// Check the session counter
//
$sessionCounter = $decoded_token["session_counter"]; // From the req
$seenSessionCounter = $ad['counter']; // From DB
$scDiff = $seenSessionCounter - $sessionCounter;
if ($scDiff > 0) {
	debug("Replayed session counter=" . $sessionCounter . ', seen=' . $seenSessionCounter);
	sendResp(S_REPLAYED_OTP);
	exit;
} else {
	debug("Session counter OK (" . $sessionCounter . ")");
}

//// Check the time stamp
//
if ($scDiff == 0) { // Same use session, check time stamp diff
	$ts = $decoded_token['timestamp'];
	$seenTs = ($ad['high'] << 16) + $ad['low'];
	$tsDiff = $ts - $seenTs;
	if ($tsDiff <= 0) {
		debug("Replayed time stamp=" . $ts . ', seen=' . $seenTs);
		sendResp(S_REPLAYED_OTP);
		exit;
	} else {
		updDB($ad['id'], $decoded_token, $client);
		$tsDelta = $tsDiff * TS_SEC;
		debug("Timestamp OK (" . $ts . ") delta count=" . $tsDiff .
		'-> delta secs=' . $tsDelta);
	}

	//// Check the real time
	//
	
	if ($ad['chk_time']) {
		$lastTime = strtotime($ad['accessed']);
		debug('Last accessed: '.$ad['accessed'].', '.$lastTime.', '.date("F j, Y, g:i a", $lastTime));
		$elapsed = time() - $lastTime;
		debug('Elapsed time from last validation: ' . $elapsed . ' secs');
		$deviation = abs($elapsed - $tsDelta);
		$percent = truncate(100*$deviation/$elapsed, 8) . '%';
		debug("Key time deviation vs. elapsed time=".$deviation.' secs ('.
			$percent.')');
		if ($deviation > TS_TOLERANCE * $elapsed) {
			debug("Is the OTP generated from a real crypto key?");
			sendResp(S_SECURITY_ERROR);
			exit;
		}
	}
} // End check time stamp

//// Check the high counter
//
//$hi = $decoded_token["high"]; // From the req
//$seenHi = $ad['high']; // From DB
//$hiDiff = $seenHi - $hi;
//if ($scDiff == 0 && $hiDiff > 0) {
//	debug("Replayed hi counter=".$hi.', seen='.$seenHi);
//	sendResp(S_REPLAYED_OTP);
//	exit;
//} else {
//	debug("Hi counter OK (".$hi.")");
//}

//// Check the low counter
//
//$lo = $decoded_token["low"]; // From the req
//$seenLo = $ad['low']; // From DB
//$loDiff = $seenLo - $lo;
//if ($scDiff == 0 && $hiDiff == 0 && $loDiff >= 0) {
//	debug("Replayed low counter=".$lo.', seen='.$seenLo);
//	sendResp(S_REPLAYED_OTP);
//	exit;
//} else {
//	debug("Lo counter OK (".$lo.")");
//}

//// Update the DB only upon validation success
//
if (updDB($ad['id'], $decoded_token, $client)) {
	debug('Validation database updated');
	sendResp(S_OK);
} else {
	debug('Failed to update validation database');
	sendResp(S_BACKEND_ERROR);
}

//////////////////////////
// 		Functions
//////////////////////////

function sendResp($status, $info = null) {
	global $ad, $apiKey;

	if ($status == null) {
		$status = S_BACKEND_ERROR;
	}
	$a['status'] = $status;
	$a['t']=getUTCTimeStamp();
	
	if ($info != null) {
		echo 'info='.($a['info'] = $info).PHP_EOL;
	}
	
	$h = sign($a, $apiKey);
	echo 'h='.$h.PHP_EOL;
	echo 't='.$a['t'].PHP_EOL;
	echo 'status='.$status.PHP_EOL;
	echo PHP_EOL;

} // End sendResp

function updDB($keyid, $new, $client) {
	$stmt = 'UPDATE yubikeys SET ' .
	'accessed=NOW(),' .
	'counter=' . $new['session_counter'] . ',' .
	'low=' . $new['low'] . ',' .
	'high=' . $new['high'] .
	' WHERE id=' . $keyid;
	if (!query($stmt)) {
		$err = 'Failed to update validation data of key: ' . $keyid . ' by ' . $stmt;
		debug($err);
		writeLog($err);
		return false;
	}

	addHist(0, $_SERVER['REMOTE_ADDR'], $keyid, $client);

	return true;
}
?>
