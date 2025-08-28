<?php

$nameErr = $check = $emailErr = "";
include 'components/connect.php';

session_start();

if (isset($_SESSION['user_id'])) {
    $user_id = $_SESSION['user_id'];
} else {
    $user_id = '';
}

if (isset($_POST['submit'])) {

    $name = $_POST['name'];
    $name = filter_var($name, FILTER_SANITIZE_STRING);
    $email = $_POST['email'];
    $email = filter_var($email, FILTER_SANITIZE_EMAIL);
    $pass = $_POST['pass'];
    $pass = filter_var($pass, FILTER_SANITIZE_STRING);
    $cpass = $_POST['cpass'];
    $cpass = filter_var($cpass, FILTER_SANITIZE_STRING);

    $select_user = $conn->prepare("SELECT * FROM `users` WHERE email = ?");
    $select_user->execute([$email]);
    $row = $select_user->fetch(PDO::FETCH_ASSOC);

    if ($select_user->rowCount() > 0) {
        $emailErr = "Email already exists!";
    } else {

        if (!preg_match("/^[a-z]{5,20}$/", $name)) {
            $nameErr = "Username must contain only lowercase letters (5-20 characters).";
        } elseif (!preg_match('/^[a-z0-9._%+-]+@gmail\.com$/', $email)) {
            $emailErr = "Email must be a valid Gmail address with lowercase letters.";
        } elseif (!preg_match('/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).{8,}$/', $pass)) {
            $check = "Password must be at least 8 characters, include at least one uppercase letter, one lowercase letter, one number, and one special character.";
        } elseif ($pass !== $cpass) {
            $check = 'Confirm password does not match!';
        } else {
            $hashed_pass = sha1($pass);
            $insert_user = $conn->prepare("INSERT INTO `users` (name, email, password) VALUES (?, ?, ?)");
            $insert_user->execute([$name, $email, $hashed_pass]);
            $message[] = 'Registered successfully, login now please!';
        }
    }
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    
    <!-- Font Awesome CDN link -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.1.1/css/all.min.css">

    <!-- Custom CSS file link -->
    <link rel="stylesheet" href="css/style.css">
</head>
<style>
.err {color: #FF0001;}
</style>
<body>
    
<?php include 'components/user_header.php'; ?>

<section class="form-container">

    <form action="" method="post">
        <h3>Register Now.</h3>
        <input type="text" name="name" required placeholder="enter your username" maxlength="20" class="box" pattern="[a-z]{5,20}" title="Username must contain only lowercase letters (5-20 characters).">
        <p class="err"><?php echo $nameErr; ?></p>
        <input type="email" name="email" required placeholder="enter your Gmail address" maxlength="50" class="box" pattern="^[a-z0-9._%+-]+@gmail\.com$" title="Email must be a valid Gmail address with lowercase letters." oninput="this.value = this.value.replace(/\s/g, '')">
        <p class="err"><?php echo $emailErr; ?></p>
        <input type="password" name="pass" required placeholder="enter your password" maxlength="20" class="box" oninput="this.value = this.value.replace(/\s/g, '')" pattern="^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).{8,}$" title="Password must be at least 8 characters, including an uppercase letter, a lowercase letter, a number, and a special character.">
        <input type="password" name="cpass" required placeholder="confirm your password" maxlength="20" class="box" oninput="this.value = this.value.replace(/\s/g, '')">
        <p class="err"><?php echo $check; ?></p>
        <input type="submit" value="register now" class="btn" name="submit">
        <p>Already have an account?</p>
        <a href="user_login.php" class="option-btn">Login Now.</a>
    </form>

</section>

<?php include 'components/footer.php'; ?>

<script src="js/script.js"></script>

</body>
</html>
