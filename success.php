<?php
// Check if the user is logged in, if not then redirect him to login page
if(!isset($_COOKIE["loggedin"]) || $_COOKIE["loggedin"] !=1){
    header("location: login.php");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Success</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body{ font: 14px sans-serif; text-align: center; }
    </style>
</head>
<body>
    <h1 class="my-5">Hi, <b><?php echo htmlspecialchars($_COOKIE["username"]); ?></b>. You have logged in.</h1>
    <p>
        <a href="logout.php" class="btn btn-danger ml-3">Log out</a>
    </p>
</body>
</html>