<?php
// Arquivo: login.php
session_start();
require 'db.php';


if ($_SERVER['REQUEST_METHOD'] == 'POST') {
$username = trim($_POST['username']);
$password = $_POST['password'];


$stmt = $pdo->prepare('SELECT * FROM usuarios WHERE username = ?');
$stmt->execute([$username]);
$user = $stmt->fetch();


if ($user && password_verify($password, $user['senha'])) {
$_SESSION['user_id'] = $user['id'];
$_SESSION['username'] = $user['username'];
header('Location: painel.php');
exit;
} else {
$_SESSION['error'] = 'Usuário ou senha incorretos.';
header('Location: login.html');
exit;
}
}
?>