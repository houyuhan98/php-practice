<?php
    require_once "config.php";

    $email = $_COOKIE["username"]."@usc.edu";
    $token = md5($email).rand(10,9999);
    $expFormat = mktime(
        date("H"), date("i"), date("s"), date("m") ,date("d")+1, date("Y")
        );
    
    $expDate = date("Y-m-d H:i:s",$expFormat);
 
    $sql = "UPDATE users set token = ?, exp_date = ? WHERE username = ?";
    if($stmt = mysqli_prepare($link, $sql)){
        // Bind variables to the prepared statement as parameters
        mysqli_stmt_bind_param($stmt, "sss", $param_token, $param_expDate, $param_username);
        
        // Set parameters
        $param_token = $token;
        $param_expDate = $expDate;
        $param_username = $_COOKIE["username"];
        
        // Attempt to execute the prepared statement
        if(mysqli_stmt_execute($stmt)){
            //echo "token, expiry date set successfully.";
        } else{
            echo "Something went wrong. Please try again later.";
        }

        // Close statement
        mysqli_stmt_close($stmt);
    }
    mysqli_close($link);
 
    $link = "<a href='localhost/user/reset.php?username=".$_COOKIE["username"]."&token=".$token."'>Click To Reset password</a>";
    
    use PHPMailer\PHPMailer\PHPMailer;
    use PHPMailer\PHPMailer\Exception;
    require_once('C:\xampp\composer\vendor\autoload.php');
 
    $mail = new PHPMailer();
 
    $mail->CharSet =  "utf-8";
    $mail->IsSMTP();
    // enable SMTP authentication
    $mail->SMTPAuth = true;                  
    // GMAIL username
    $mail->Username = "ctf2team4@gmail.com";
    // GMAIL password
    $mail->Password = "Ctf2team4emailtest!";
    $mail->SMTPSecure = "ssl";  
    // sets GMAIL as the SMTP server
    $mail->Host = "smtp.gmail.com";
    // set the SMTP port for the GMAIL server
    $mail->Port = "465";
    $mail->From='noreply@team4system.com';
    $mail->FromName='team 4 system';
    $mail->AddAddress($email, $_COOKIE["username"]);
    $mail->Subject  =  'Reset Password';
    $mail->IsHTML(true);
    $mail->Body = 'Click On This Link to Reset Password '.$link.'';
    if($mail->Send())
    {
      echo "Email sent. Please check Your Email (spam folder as well) and Click on the link sent to your email.";
    }
    else
    {
      echo "Mail Error - >".$mail->ErrorInfo;
    }
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Email</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body{ font: 14px sans-serif; text-align: center; }
    </style>
</head>
<body>
    <p>
        <a href="login.php" class="btn btn-info ml-3">Back to Home</a>
    </p>
</body>
</html>