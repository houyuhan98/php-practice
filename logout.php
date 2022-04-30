<?php
    setcookie("username", "", time() - 3600, "/");
    setcookie("loggedin", 0, time() - 3600, "/");
    echo "You have logged out."; 
    header("location: login.php");
    exit;      
?>


