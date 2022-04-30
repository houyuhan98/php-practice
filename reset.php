<?php
require_once "config.php";

$expired=false;
$password_err="";
$confirm_password_err ="";
$password="";
$confirm_password="";

if($_SERVER["REQUEST_METHOD"] == "GET"){
    $username = $_GET['username'];
    $token = $_GET['token'];
    $curDate = date("Y-m-d H:i:s");

    $sql = "SELECT exp_date FROM users WHERE username = ? and token = ?";
        
    if($stmt = mysqli_prepare($link, $sql)){
        // Bind variables to the prepared statement as parameters
        mysqli_stmt_bind_param($stmt, "ss", $param_username, $param_token);
        
        // Set parameters
        $param_username = $username;
        $param_token = $token;
        
        // Attempt to execute the prepared statement
        if(mysqli_stmt_execute($stmt)){
            /* store result */
            mysqli_stmt_store_result($stmt);
            
            if(mysqli_stmt_num_rows($stmt) == 1){
                mysqli_stmt_bind_result($stmt, $expDate);
                    if(mysqli_stmt_fetch($stmt)){
                        if($expDate<$curDate){
                            $expired=true;
                        }
                    }
            }
        } else{
            echo "Something went wrong. Please try again later.";
        }

        // Close statement
        mysqli_stmt_close($stmt);
    }

    if (isset($_GET["password"])) {
        $password=htmlspecialchars($_GET["password"]);
    } else {
        $password="";
    }
    if (isset($_GET["confirm_password"])) {
        $confirm_password=htmlspecialchars($_GET["confirm_password"]);
    } else {
        $confirm_password="";
    }

    if(empty(trim($password))){
        $password_err = "Please enter a password."; 
    } elseif(strlen(trim($password)) < 8){
        $password_err = "Password must have at least 8 characters.";
    } elseif(strlen(trim($password)) > 255){
        $password_err = "Password cannot exceed 255 characters.";
    } elseif(!preg_match('/[a-z]/', trim($password))){
        $password_err= "Password need to contain at least 1 lower case.";
    } elseif(!preg_match('/[A-Z]/', trim($password))){
        $password_err= "Password need to contain at least 1 upper case.";
    } elseif(!preg_match('/[0-9]/', trim($password))){
        $password_err= "Password need to contain at least 1 number.";
    } elseif(!preg_match('/[\'^£$%&*()}{@#~?><>,|=_+!-]/', trim($password))){
        $password_err= "Password need to contain at least 1 special character.";
    } elseif(stripos(trim($password),trim($username))!=false){
        $password_err= "Password can not contain your username.";
    } else{
	  // check if password contains a common password string
        function commonPasswordCheck($password) {
            $lines = file('common_password.txt');
            foreach($lines as $line) {    
                if(stripos($password, trim($line))!=false) {
                    return "Cannot contain commonly used string: ".$line;
                }
            }
            return "";
        }
    
        $common_string_password_err = commonPasswordCheck(trim($password));

    	  // Check for repeating characters
        function repeatingCharsCheck($password) {
            preg_match_all('/(.)\1+/', $password, $matches);
            $result = array_combine($matches[0], array_map('strlen', $matches[0]));
    
            foreach ($result as $key => $val) {
                // If repeating sequence is longer than 2, throw an error
                if ($val > 2) {
                    return "Cannot have numbers/characters that repeat more than twice";
                }
            }
        
            return "";
        }
        $repeat_chars_password_err = repeatingCharsCheck(trim($password));

        // Check if an ascii value is a letter or number
        function isLetterOrNumber($charAscii) {
            if ( $charAscii < 48 || $charAscii > 122 || ($charAscii > 57 && $charAscii < 65) || ($charAscii > 90 && $charAscii < 97) ) {
                return false;
            }
            return true;
        }

        // Check for consecutive sequence
        function consecutiveSequenceCheck($password) {
            $longestConsecutiveSequence = 0;
            $tempConsecutiveSequence = 0;
            $lastChar = " ";
            $direction = 0;

            // Loop through string
            $array = str_split($password);
            foreach ($array as $char) {
                // Convert to ascii so that both letters and numbers can be compared
                $lastCharAscii = ord($lastChar);
                $charAscii = ord($char);            
 
                // If char is letter or number then for consecutive sequence
                if ( isLetterOrNumber($lastCharAscii) && isLetterOrNumber($charAscii) ) {

                    // Check if one more or less than char
                    if ( abs($charAscii - $lastCharAscii) == 1 ) {

                        // Check for same direction
                        if ( ($lastCharAscii - $charAscii) == $direction) {
                            ++$tempConsecutiveSequence;
                        }
                        else {
                            $tempConsecutiveSequence = 2;
                            $direction = $lastCharAscii - $charAscii;
                        }

                        $longestConsecutiveSequence = max($longestConsecutiveSequence, $tempConsecutiveSequence);
                        if ($longestConsecutiveSequence > 2) {
                            return "Cannot have a sequence of consecutive numbers/characters longer than 2";
                        }
                    }
                } 
                else {
                    // If char is not a letter or number, reset direction
                    $direction = 0;
                }

                // Update lastChar
                $lastChar = $char;
            }

            return "";
        }
	  $consecutive_seq_password_err = consecutiveSequenceCheck(trim($password));

	  if (!empty($repeat_chars_password_err)) {
            $password_err = $repeat_chars_password_err;
        }
        if (!empty($consecutive_seq_password_err)) {
            $password_err = $consecutive_seq_password_err;
        }
	  if (!empty($common_string_password_err)) {
            $password_err = $common_string_password_err;
        }
    }

    if(empty(trim($confirm_password))){
        $confirm_password_err = "Please confirm password.";     
    } else{
        if(empty($password_err) && (trim($password) != trim($confirm_password))){
            $confirm_password_err = "Password did not match.";
        }
    }

    if(empty($password_err) && empty($confirm_password_err)){
        
        // Prepare an insert statement
        $sql = "UPDATE users set password=?, salt=?, encrypted_password=?, token=?, exp_date=? WHERE username=?";
         
        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "ssssss", $param_password, $param_salt, $param_encrypted_password, $param_token, $param_expDate, $param_username);
            
		$salt = bin2hex(random_bytes(5));
            $saltedPassword = $salt.trim($password);

            // Set parameters
            $param_username = $username;
            $param_password = md5($saltedPassword); // Creates a password hash
		$param_salt = $salt;
            $param_encrypted_password = openssl_encrypt(trim($password), "AES-128-CTR", "ctf2team4", 0, '1234567891011121'); // Store a version of encrypted password for us to decrypt in ctf
            $param_token = NULL;
            $param_expDate = NULL;
            
            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                header("location: login.php");
                echo "<script>alert('account password updated successfully.');</script>";
            } else{
                echo "Something went wrong. Please try again later.";
            }

            // Close statement
            mysqli_stmt_close($stmt);
        }
    }
    // Close connection
    mysqli_close($link);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Reset Password</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body{ font: 14px sans-serif; }
        .wrapper{ width: 460px; padding: 20px; margin:auto;}
    </style>
</head>
<body>
    <div class="wrapper">
        <h2 style="text-align: center;">Reset Password</h2>
        <?php if(!$expired){ ?>
            <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="get">  
            <input type="hidden" name="username" value="<?php echo $username;?>">
            <input type="hidden" name="token" value="<?php echo $token;?>">

                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" placeholder="please follow the password policy" class="form-control <?php echo (!empty($password_err)) ? 'is-invalid' : ''; ?>">
                    <span class="invalid-feedback"><?php echo $password_err; ?></span>
                </div>
                <div class="form-group">
                    <label>Confirm Password</label>
                    <input type="password" name="confirm_password" class="form-control <?php echo (!empty($confirm_password_err)) ? 'is-invalid' : ''; ?>">
                    <span class="invalid-feedback"><?php echo $confirm_password_err; ?></span>
                </div>
                <div class="form-group">
                    <input type="submit" class="btn btn-dark" value="Reset Password">
                </div>
                <p>Password Policy:</p>
                <p>1. At least 8 characters.</p>
                <p>2. At least 1 lower case.</p>
                <p>3. At least 1 upper case.</p>
                <p>4. At least 1 number.</p>
                <p>5. At least 1 special character.</p>
                <p>6. Not contain username.</p>
                <p>7. Does not substitute a letter for a similar looking number.</p>
                <p>8. Does not have series or repeats.</p>
		    <p>9. Does not have common or dictionary words.</p>
            </form>
        <?php } else{?>
            <p>This link has expired.</p>
        <?php } ?>
    </div>    
</body>
</html> 