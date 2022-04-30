<?php
require_once "config.php";

$username_err="";
$password_err="";
$username="";
$password="";

// Redirect them to the success page if they are already logged in
if(isset($_COOKIE["loggedin"]) && $_COOKIE["loggedin"]==1){
    header("location: success.php");
    exit;
}
if($_SERVER["REQUEST_METHOD"] == "GET"){
    if (isset($_GET["username"])) {
        $username=htmlspecialchars($_GET["username"]);
    } else {
        $username="";
    }
    if (isset($_GET["password"])) {
        $password=htmlspecialchars($_GET["password"]);
    } else {
        $password="";
    }

    if(empty(trim($username))){
        $username_err = "Please enter a username.";
    }
    if(strlen(trim($username)) > 50){
        $username_err = "Username cannot exceed 50 characters.";
    }
    
    if(empty(trim($password))){
        $password_err = "Please enter a password.";
    }
    if(strlen(trim($password)) > 255){
        $password_err = "Password cannot exceed 255 characters.";
    }

    if(empty($username_err) && empty($password_err)){
        // Prepare a select statement
        $sql = "SELECT username, salt, password FROM users WHERE username = ?";
        
        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "s", $param_username);
            
            // Set parameters
            $param_username = trim($username);
            
            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                // Store result
                mysqli_stmt_store_result($stmt);
                
                // Check if username exists, if yes then verify password
                if(mysqli_stmt_num_rows($stmt) == 1){                    
                    // Bind result variables
                    mysqli_stmt_bind_result($stmt, $username, $salt, $hashed_password);
                    if(mysqli_stmt_fetch($stmt)){
                        setcookie("username", $username, time() + (86400 * 30), "/");
				$saltedPassword = $salt.$password;
                        if(md5($saltedPassword)==$hashed_password){
                            setcookie("loggedin", 1, time() + (86400 * 30), "/");
                            header("location: success.php");
                        } else{
                            header("location: failure.php");
                        }
                    }
                } else{
                    header("location: failure.php");
                }
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
    <title>Log In</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body{ font: 14px sans-serif;}
        .wrapper{ width: 460px; padding: 20px; margin:auto;}
    </style>
</head>
<body>
    <div class="wrapper">
        <h2 style="text-align:center;">Log In</h2>

        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="get">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" placeholder="your usc username before @" value="<?php echo $username; ?>" class="form-control <?php echo (!empty($username_err)) ? 'is-invalid' : ''; ?>">
                <span class="invalid-feedback"><?php echo $username_err; ?></span>
            </div>    
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" class="form-control <?php echo (!empty($password_err)) ? 'is-invalid' : ''; ?>">
                <span class="invalid-feedback"><?php echo $password_err; ?></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-dark" value="Log In">
            </div>
            <p>Don't have an account? <a href="register.php">Sign up now</a>.</p>
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
    </div>
</body>
</html>